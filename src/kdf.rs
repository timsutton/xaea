//! Key derivation for AEA (kinnay FORMAT.md "Key derivation" section).
//!
//! The AEA spec spells out a set of constants ("AEA_AMK" and friends), so we
//! keep them here verbatim. See the spec for why.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// Every key in the AEA HMAC key tree is 32 bytes.
pub type Key = [u8; 32];

fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8]) -> Key {
    let mut okm = [0u8; 32];
    hkdf::Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, &mut okm)
        .expect("HKDF expand of fixed size cannot fail");
    okm
}

/// HKDF-SHA256 with caller-chosen output length.
fn hkdf_len(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) {
    hkdf::Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, out)
        .expect("HKDF expand of bounded size cannot fail");
}

/// `prefix || index` (little-endian), the info string of the indexed keys.
fn indexed_info(prefix: &[u8], index: u32) -> Vec<u8> {
    [prefix, &index.to_le_bytes()].concat()
}

/// Raw HMAC-SHA256 with no salt prefix or length suffix. The encrypted
/// root-header MAC (profile 1) is computed this way, unlike every profile-0
/// MAC, which goes through [`mac`].
pub fn mac_raw(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac as _};
    let mut mac = <Hmac<sha2::Sha256> as hmac::KeyInit>::new_from_slice(key)
        .expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
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
pub fn main_key(ikm: &[u8], main_salt: &[u8], header_4_8: &[u8], signing_point: &[u8]) -> Key {
    let info = [b"AEA_AMK".as_slice(), header_4_8, signing_point].concat();
    hkdf(ikm, main_salt, &info)
}

/// Profile-1 main key: no signing point — the IKM is the FCS symmetric
/// key recovered out-of-band and the info is `"AEA_AMK"` + bytes 4..8 of
/// the file header (the u32le profile).
pub fn main_key_sym(symkey: &[u8], main_salt: &[u8], header_4_8: &[u8]) -> Key {
    let info = [b"AEA_AMK".as_slice(), header_4_8].concat();
    hkdf(symkey, main_salt, &info)
}

pub fn root_header_key(main_key: &Key) -> Key {
    hkdf(main_key, b"", b"AEA_RHEK")
}

pub fn cluster_key(main_key: &Key, cluster_index: u32) -> Key {
    hkdf(main_key, b"", &indexed_info(b"AEA_CK", cluster_index))
}

pub fn cluster_header_key(ck: &Key) -> Key {
    hkdf(ck, b"", b"AEA_CHEK")
}

/// Segment key. `segment_index` is the cluster-**local** index (verified on
/// Xcode 27.3 b2: global index fails from cluster 1 onward).
pub fn segment_key(ck: &Key, segment_index: u32) -> Key {
    hkdf(ck, b"", &indexed_info(b"AEA_SK", segment_index))
}

/// Profile-1 key material is an 80-byte Expand output: MAC key (32) ||
/// AES-256 key (32) || IV (16). The profile-0 helpers above derive 32-byte
/// HMAC keys only; encrypted archives need the full triple.
pub const DATA_KEY_MATERIAL_LEN: usize = 80;

/// Profile-1 root-header material from the main key: Expand from
/// Extract(main key, 32 zero bytes), info `"AEA_RHEK"`. The archive's main
/// salt is used only for the main key itself.
pub fn root_header_material(main_key: &Key) -> [u8; DATA_KEY_MATERIAL_LEN] {
    let mut out = [0u8; DATA_KEY_MATERIAL_LEN];
    hkdf_len(main_key, &[0u8; 32], b"AEA_RHEK", &mut out);
    out
}

/// Profile-1 cluster-header material from a cluster key: Expand from
/// Extract(cluster key, 32 zero bytes), info `"AEA_CHEK"`.
pub fn cluster_header_material(ck: &Key) -> [u8; DATA_KEY_MATERIAL_LEN] {
    let mut out = [0u8; DATA_KEY_MATERIAL_LEN];
    hkdf_len(ck, &[0u8; 32], b"AEA_CHEK", &mut out);
    out
}

/// Profile-1 segment material from a cluster key, keyed by the cluster-local
/// segment index: Expand from Extract(cluster key, 32 zero bytes), info
/// `"AEA_SK" + u32le(index)`.
pub fn segment_material(ck: &Key, segment_index: u32) -> [u8; DATA_KEY_MATERIAL_LEN] {
    let mut out = [0u8; DATA_KEY_MATERIAL_LEN];
    hkdf_len(
        ck,
        &[0u8; 32],
        &indexed_info(b"AEA_SK", segment_index),
        &mut out,
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    fn tohex(b: &[u8]) -> String {
        b.iter().fold(String::new(), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
    }

    // Deterministic reference vectors from scripts/make_test_aea.py (seed 1).
    const IKM: &str = "cf79c803a652844e73ef07a4adca87326100c2e832e235f910435197540b0c7b";
    const SALT: &str = "fcf9f813dd58c073b00f90944fa7f451f75e6411f938a43b60fd9ba7a02a84b2";
    const POINT: &str = "04c05b71ed588f050e3e407f278d3b56621bc9c89e5c09e73cc3e35052f7\
                         9440f9fd2c883b2e923e805e0790bca7a35f1537581221cab92487f27bded0aa2f5350";
    const MAINKEY: &str = "54b3c3698358a622f54dd76f6b6c62e028df7cccf098be55c2f66335b14ad3fd";
    const ROOTKEY: &str = "cc07bdd7909a3a1a8d4c335d8a6c9f49a8ad1d03f487eb15a9a5a263d404bb5e";
    const CK0: &str = "8360b797ea4f3e8cf907b8dbeb8b69d433951fc6feb6ce72664114b10f91ea06";
    const CHEK0: &str = "20f8daea78d9c94de7c59e6cb2099290d9a92eb0b30d290b03c62332264a8d6b";
    const SEG0: &str = "c17bf80c8279a38a9ba8806e75ddc33899cff3205b51406aa2e60c9ba42b945a";

    #[test]
    fn kdf_chain_matches_python_reference() {
        let mk = main_key(
            &unhex(IKM),
            &unhex(SALT),
            b"\x00\x00\x00\x00",
            &unhex(POINT),
        );
        assert_eq!(tohex(&mk), MAINKEY, "main key (info AEA_AMK||hdr48||point)");
        assert_eq!(tohex(&root_header_key(&mk)), ROOTKEY);
        let ck = cluster_key(&mk, 0);
        assert_eq!(tohex(&ck), CK0);
        assert_eq!(tohex(&cluster_header_key(&ck)), CHEK0);
        assert_eq!(tohex(&segment_key(&ck, 0)), SEG0);
        // local index must matter
        assert_ne!(segment_key(&ck, 0), segment_key(&ck, 1));
    }

    #[test]
    fn mac_layout_is_salt_data_len() {
        use hmac::{KeyInit, Mac};
        let k = [7u8; 32];
        let (d, s) = (b"hello".as_slice(), b"salt".as_slice());
        let mut manual: Vec<u8> = s.to_vec();
        manual.extend_from_slice(d);
        manual.extend_from_slice(&(s.len() as u64).to_le_bytes());
        let mut m = Hmac::<Sha256>::new_from_slice(&k).unwrap();
        m.update(&manual);
        let expect: [u8; 32] = m.finalize().into_bytes().into();
        assert_eq!(mac(&k, d, s), expect);
        assert_ne!(mac(&k, d, b""), mac(&k, d, s));
    }
}
