//! Generate an independent profile-1 archive with Apple's encoder.
#![cfg(target_os = "macos")]

use std::{fs, process::Command};

#[test]
fn decrypt_matches_plaintext_and_refuses_damaged_images() {
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    let mut plain = vec![0x61; (8 << 20) + 17];
    // Incompressible stored segments, compressed segments, and a short tail.
    let mut state = 42u32;
    for b in &mut plain[..1 << 20] {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        *b = state as u8;
    }
    fs::write(dir.join("original"), &plain).unwrap();
    fs::write(dir.join("key"), [0x11; 32]).unwrap();
    let encoded = Command::new("/usr/bin/aea")
        .current_dir(dir)
        .args([
            "encrypt",
            "-profile",
            "1",
            "-a",
            "lzfse",
            "-b",
            "4k",
            "-checksum",
            "sha256",
            "-padding",
            "4k",
            "-key-value",
            &format!("hex:{}", "11".repeat(32)),
            "-i",
            "original",
            "-o",
            "image.aea",
        ])
        .output()
        .unwrap();
    assert!(
        encoded.status.success(),
        "{}",
        String::from_utf8_lossy(&encoded.stderr)
    );

    let decrypt = || {
        Command::new(env!("CARGO_BIN_EXE_xaea"))
            .current_dir(dir)
            .args([
                "decrypt",
                "image.aea",
                "--key-file",
                "key",
                "-o",
                "image.dmg",
            ])
            .output()
            .unwrap()
    };
    let ok = decrypt();
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert_eq!(fs::read(dir.join("image.dmg")).unwrap(), plain);
    fs::write(dir.join("image.dmg"), b"existing").unwrap();
    assert!(!decrypt().status.success());
    assert_eq!(fs::read(dir.join("image.dmg")).unwrap(), b"existing");
    fs::remove_file(dir.join("image.dmg")).unwrap();

    let archive = fs::read(dir.join("image.aea")).unwrap();
    for offset in [45, 200, archive.len() / 2, archive.len() - 1] {
        let mut corrupted = archive.clone();
        corrupted[offset] ^= 1;
        fs::write(dir.join("image.aea"), corrupted).unwrap();
        assert!(
            !decrypt().status.success(),
            "accepted corruption at {offset}"
        );
        assert!(!dir.join("image.dmg").exists());
    }
    fs::write(dir.join("image.aea"), archive).unwrap();
    fs::write(dir.join("key"), [0x22; 32]).unwrap();
    assert!(!decrypt().status.success());
    assert!(!dir.join("image.dmg").exists());
}
