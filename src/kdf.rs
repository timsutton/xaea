//! Key derivation for AEA (kinnay FORMAT.md "Key derivation" section).
//!
//! The AEA spec spells out a set of constants ("AEA_AMK" and friends), so we
//! keep them here verbatim. See the spec for why.

use hmac::{Hmac, Mac};
use sha2::Sha256;

pub fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut okm = vec![0u8; len];
    hkdf::Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, &mut okm)
        .expect("HKDF expand of fixed size cannot fail");
    okm
}

/// MAC calculation (kinnay FORMAT.md): HMAC-SHA256 over `salt || data || u64le(len(salt))`.
pub fn mac(key: &[u8], data: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key size");
    m.update(salt);
    m.update(data);
    m.update(&(salt.len() as u64).to_le_bytes());
    m.finalize().into_bytes().into()
}

/// Main key. For profile 0 the IKM is the 32-byte value from the public-key
/// section and the info includes bytes 4..8 of the file header.
/// Info string: "AEA_AMK" + file header bytes 4..8 + (if the profile signs)
/// the uncompressed X9.62 encoding of the signing public key. Verified
/// against the real Xcode 27.3 b2 artifact.
pub fn main_key(ikm: &[u8], main_salt: &[u8], header_4_8: &[u8], signing_point: &[u8]) -> Vec<u8> {
    let mut info = b"AEA_AMK".to_vec();
    info.extend_from_slice(header_4_8);
    info.extend_from_slice(signing_point);
    hkdf(ikm, main_salt, &info, 32)
}

pub fn root_header_key(main_key: &[u8]) -> Vec<u8> {
    hkdf(main_key, b"", b"AEA_RHEK", 32)
}

pub fn cluster_key(main_key: &[u8], cluster_index: u32) -> Vec<u8> {
    let mut info = b"AEA_CK".to_vec();
    info.extend_from_slice(&cluster_index.to_le_bytes());
    hkdf(main_key, b"", &info, 32)
}

pub fn cluster_header_key(ck: &[u8]) -> Vec<u8> {
    hkdf(ck, b"", b"AEA_CHEK", 32)
}

/// Segment key. `segment_index` is the cluster-**local** index (verified on
/// Xcode 27.3 b2: global index fails from cluster 1 onward).
pub fn segment_key(ck: &[u8], segment_index: u32) -> Vec<u8> {
    let mut info = b"AEA_SK".to_vec();
    info.extend_from_slice(&segment_index.to_le_bytes());
    hkdf(ck, b"", &info, 32)
}
