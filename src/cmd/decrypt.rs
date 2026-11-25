//! Decode the symmetric-key AEA envelope used by restore disk images.
use super::open_archive;
use crate::cli::DecryptArgs;
use crate::envelope::{Checksum, Compression, ROOT_HEADER_LEN, RootHeader};
use crate::exit::{Exit, WithExit};
use crate::kdf::{self, Key};
use anyhow::{Context, Result, ensure};
use base64ct::{Base64, Encoding};
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, KeyInit, Mac};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::FileExt;
use std::path::Path;

fn read_key(path: &Path) -> Result<Key> {
    let mut bytes = Vec::new();
    File::open(path)?.take(128).read_to_end(&mut bytes)?;
    if let Ok(raw) = bytes.as_slice().try_into() {
        return Ok(raw);
    }
    let encoded = std::str::from_utf8(&bytes)
        .ok()
        .and_then(|s| s.trim_end().strip_prefix("base64:"));
    let mut key = [0; 32];
    ensure!(
        encoded
            .and_then(|s| Base64::decode(s, &mut key).ok())
            .is_some_and(|k| k.len() == 32)
            && bytes.len() < 128,
        "expected a raw 32-byte archive key or a base64: encoded key"
    );
    Ok(key)
}

// The first 32 HKDF bytes are the HMAC key, followed by AES-256 key and CTR IV.
struct Material([u8; 80]);

impl Material {
    fn derive(key: &Key, info: &[u8]) -> Self {
        Self(kdf::hkdf(key, &[], info))
    }

    fn verify(&self, data: &[u8], salts: &[&[u8]], tag: &[u8]) -> Result<()> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0[..32])?;
        let mut len = 0u64;
        for salt in salts {
            mac.update(salt);
            len += salt.len() as u64;
        }
        mac.update(data);
        mac.update(&len.to_le_bytes());
        mac.verify_slice(tag).context("HMAC mismatch")
    }

    fn decrypt(&self, bytes: &mut [u8]) {
        ctr::Ctr128BE::<aes::Aes256>::new(
            self.0[32..64].try_into().expect("32-byte key"),
            self.0[64..].try_into().expect("16-byte IV"),
        )
        .apply_keystream(bytes);
    }
}

fn take<'a>(input: &mut &'a [u8], len: usize) -> Result<&'a [u8]> {
    input.split_off(..len).context("truncated archive")
}

struct Image<'a> {
    root: RootHeader,
    key: Key,
    next_mac: &'a [u8],
    input: &'a [u8],
}

impl<'a> Image<'a> {
    fn open(mut input: &'a [u8], supplied: &Key) -> Result<Self> {
        let size = input.len() as u64;
        ensure!(take(&mut input, 4)? == b"AEA1", "expected AEA1 archive");
        let profile = take(&mut input, 4)?;
        ensure!(profile == [1, 0, 0, 0], "decrypt requires AEA profile 1");
        let auth_len = u32::from_le_bytes(*take(&mut input, 4)?.first_chunk().unwrap());
        let auth = take(&mut input, auth_len as usize)?;
        let key = kdf::main_key(supplied, take(&mut input, 32)?, profile, &[]);
        let tag = take(&mut input, 32)?;
        let mut header = take(&mut input, ROOT_HEADER_LEN)?.to_vec();
        let next_mac = take(&mut input, 32)?;
        let material = Material::derive(&key, b"AEA_RHEK");
        material
            .verify(&header, &[next_mac, auth], tag)
            .context("root header authentication failed (wrong key or damaged archive)")?;
        material.decrypt(&mut header);
        let root = RootHeader::parse(&header)?;
        ensure!(
            root.encarchive_size == size,
            "encrypted archive size mismatch"
        );
        ensure!(
            root.compression == Compression::Lzfse && root.checksum == Checksum::Sha256,
            "decrypt supports LZFSE/SHA-256 images (found {}/{})",
            root.compression,
            root.checksum
        );
        ensure!(
            (1..=256 << 20).contains(&root.segment_size)
                && (1..=256 << 10).contains(&root.segments_per_cluster),
            "invalid cluster geometry"
        );
        Ok(Self {
            root,
            key,
            next_mac,
            input,
        })
    }

    fn write(mut self, file: &File) -> Result<()> {
        let cap = self.root.segments_per_cluster as usize;
        let mut offset = 0;
        let cluster_size = u64::from(self.root.segment_size) * cap as u64;
        let clusters = self.root.original_size.div_ceil(cluster_size);
        ensure!(clusters <= u64::from(u32::MAX) + 1, "too many clusters");
        for cluster in 0..clusters {
            let ck = kdf::cluster_key(&self.key, cluster as u32);
            let material = Material::derive(&ck, b"AEA_CHEK");
            let mut headers = take(&mut self.input, cap * 40)?.to_vec();
            let tags = take(&mut self.input, (cap + 1) * 32)?;
            material
                .verify(&headers, &[tags], self.next_mac)
                .with_context(|| format!("cluster {cluster} authentication failed"))?;
            self.next_mac = &tags[..32];
            material.decrypt(&mut headers);

            let mut jobs = Vec::new();
            for (index, entry) in headers.as_chunks::<40>().0.iter().enumerate() {
                let orig = u32::from_le_bytes(*entry.first_chunk().unwrap());
                let comp = u32::from_le_bytes(*entry[4..].first_chunk().unwrap());
                let expected =
                    (self.root.original_size - offset).min(u64::from(self.root.segment_size));
                ensure!(
                    u64::from(orig) == expected && comp <= orig && (comp == 0) == (orig == 0),
                    "invalid sizes in cluster {cluster}, segment {index}"
                );
                if orig == 0 {
                    continue;
                }
                jobs.push(Segment {
                    offset,
                    orig: orig as usize,
                    data: take(&mut self.input, comp as usize)?,
                    checksum: &entry[8..],
                    tag: &tags[(index + 1) * 32..(index + 2) * 32],
                });
                offset += u64::from(orig);
            }
            // Bound simultaneous ciphertext and plaintext buffers for large segments.
            let concurrency = (128 << 20) / (2 * self.root.segment_size as usize);
            jobs.par_iter()
                .with_min_len(jobs.len().div_ceil(concurrency.max(1)))
                .enumerate()
                .try_for_each(|(i, seg)| {
                    seg.write(file, &ck, i as u32)
                        .with_context(|| format!("cluster {cluster}, segment {i}"))
                })?;
        }
        if !self.input.is_empty() {
            let padding_key: Key = kdf::hkdf(&self.key, &[], b"AEA_PAK");
            let mut mac = Hmac::<Sha256>::new_from_slice(&padding_key)?;
            mac.update(self.input);
            mac.verify_slice(self.next_mac)
                .context("padding authentication failed")?;
        }
        Ok(())
    }
}

struct Segment<'a> {
    offset: u64,
    orig: usize,
    data: &'a [u8],
    checksum: &'a [u8],
    tag: &'a [u8],
}

impl Segment<'_> {
    fn write(&self, file: &File, ck: &Key, index: u32) -> Result<()> {
        let material = Material::derive(ck, &kdf::indexed_info(b"AEA_SK", index));
        let mut data = self.data.to_vec();
        material.verify(&data, &[], self.tag)?;
        material.decrypt(&mut data);
        if data.len() != self.orig {
            let mut plain = vec![0; self.orig + 1];
            ensure!(
                lzfse::decode_buffer(&data, &mut plain) == Ok(self.orig),
                "invalid LZFSE segment"
            );
            plain.truncate(self.orig);
            data = plain;
        }
        ensure!(
            &Sha256::digest(&data)[..] == self.checksum,
            "segment checksum mismatch"
        );
        file.write_all_at(&data, self.offset)
            .context("write disk image")
    }
}

pub fn run(args: &DecryptArgs) -> Result<()> {
    let key = read_key(&args.key_file)
        .context("read archive key")
        .with_exit(Exit::Unreadable)?;
    let src = open_archive(&args.file)?;
    let image = Image::open(&src.map, &key).with_exit(Exit::Rejected)?;
    if args.output.symlink_metadata().is_ok() {
        crate::exit::bail_exit!(
            Exit::Extraction,
            "output already exists: {}",
            args.output.display()
        );
    }
    let parent = args
        .output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let output = tempfile::NamedTempFile::new_in(parent)
        .context("create temporary disk image")
        .with_exit(Exit::Extraction)?;
    image.write(output.as_file()).with_exit(Exit::Extraction)?;
    output
        .persist_noclobber(&args.output)
        .with_context(|| format!("publish {}", args.output.display()))
        .with_exit(Exit::Extraction)?;
    Ok(())
}
