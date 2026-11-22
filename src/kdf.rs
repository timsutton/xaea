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

/// `prefix || index` (little-endian), the info string of the indexed keys.
fn indexed_info(prefix: &[u8], index: u32) -> Vec<u8> {
    [prefix, &index.to_le_bytes()].concat()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    fn tohex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
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
