//! Restore images inside IPSWs, local and over HTTP: listing disk images by
//! their BuildManifest roles, picking one, and decrypting it straight from
//! a URL. The URL cases run against a tiny range-serving HTTP server on
//! localhost, so no test touches the internet. Uses the synthetic `p1.ipsw`
//! from `scripts/make_test_aea.py --profile1`.

mod common;

use common::{build_archive, xaea};
use serde_json::Value;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Output;

fn run(args: &[&str]) -> Output {
    let out = xaea().args(args).output().expect("run xaea");
    assert!(
        out.status.code().is_some(),
        "xaea died from a signal on {args:?}"
    );
    out
}

fn code(args: &[&str]) -> i32 {
    run(args).status.code().unwrap()
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// Serve the files of `dir` on localhost with `Range` support (or without
/// it, to test the refusal); returns the base URL. One thread per
/// connection, one request per connection.
fn serve(dir: PathBuf, ranges: bool) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            let dir = dir.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(conn.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let path = line.split(' ').nth(1).unwrap_or("/").to_owned();
                let mut range = None;
                loop {
                    let mut h = String::new();
                    if reader.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
                        break;
                    }
                    if let Some(v) = h.to_ascii_lowercase().strip_prefix("range: bytes=") {
                        let (a, b) = v.trim().split_once('-').unwrap();
                        range = Some((a.parse::<usize>().unwrap(), b.parse::<usize>().unwrap()));
                    }
                }
                let Ok(body) = fs::read(dir.join(path.trim_start_matches('/'))) else {
                    let _ = conn.write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                    return;
                };
                let (head, part) = match range.filter(|_| ranges) {
                    Some((a, b)) => (
                        format!(
                            "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {a}-{b}/{}\r\n",
                            body.len()
                        ),
                        &body[a..=b],
                    ),
                    None => ("HTTP/1.1 200 OK\r\n".to_owned(), &body[..]),
                };
                let _ = conn.write_all(
                    format!(
                        "{head}Content-Length: {}\r\nConnection: close\r\n\r\n",
                        part.len()
                    )
                    .as_bytes(),
                );
                let _ = conn.write_all(part);
            });
        }
    });
    base
}

#[test]
fn inspect_lists_disk_images_by_role() {
    let Some(dir) = build_archive("ipsw-list", &["--profile1"]) else {
        return;
    };
    let o = run(&["inspect", s(&dir.join("p1.ipsw")), "--json"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["format"], "IPSW");
    assert_eq!(v["build"], "1A1");
    let images = v["images"].as_array().unwrap();
    let roles: Vec<(&str, &str, bool)> = images
        .iter()
        .map(|i| {
            (
                i["roles"][0].as_str().unwrap(),
                i["member"].as_str().unwrap(),
                i["encrypted"].as_bool().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        roles,
        [
            ("os", "100-00001-001.dmg.aea", true),
            ("restore-ramdisk", "100-00002-001.dmg", false),
            ("update-ramdisk", "100-00003-001.dmg", false),
        ]
    );
}

#[test]
fn decrypt_picks_an_ipsw_member_by_role_or_name() {
    let Some(dir) = build_archive("ipsw-local", &["--profile1"]) else {
        return;
    };
    let want = fs::read(dir.join("p1.payload")).unwrap();
    let (ipsw, pem) = (dir.join("p1.ipsw"), dir.join("p1-key.pem"));
    for (pick, out) in [
        ("os", "a.dmg"),
        ("100-00001-001.dmg.aea", "b.dmg"),
        ("100-00001-001", "c.dmg"),
    ] {
        let out = dir.join(out);
        let o = run(&[
            "decrypt",
            s(&ipsw),
            pick,
            "--key-pem",
            s(&pem),
            "-o",
            s(&out),
        ]);
        assert!(
            o.status.success(),
            "{pick}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        assert!(fs::read(&out).unwrap() == want, "{pick}: payload differs");
    }
    // Default name: the member's, minus `.aea`.
    let o = xaea()
        .current_dir(&dir)
        .args(["decrypt", "p1.ipsw", "os", "--key-pem", "p1-key.pem"])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(fs::read(dir.join("100-00001-001.dmg")).unwrap() == want);

    let no_member = run(&["decrypt", s(&ipsw), "--key-pem", s(&pem)]);
    assert_eq!(no_member.status.code(), Some(2), "an IPSW needs a member");
    assert!(
        String::from_utf8_lossy(&no_member.stderr).contains("restore-ramdisk"),
        "and lists the choices"
    );
    assert_eq!(
        code(&["decrypt", s(&ipsw), "kernel", "-o", s(&dir.join("k"))]),
        2,
        "unknown role"
    );
    assert_eq!(
        code(&[
            "decrypt",
            s(&ipsw),
            "restore-ramdisk",
            "-o",
            s(&dir.join("r"))
        ]),
        4,
        "a plain disk image is not decrypted"
    );
    assert_eq!(
        code(&[
            "decrypt",
            s(&dir.join("p1.aea")),
            "os",
            "--key-pem",
            s(&pem)
        ]),
        2,
        "a member of an archive that is not an IPSW"
    );
}

#[test]
fn decrypt_streams_from_a_url() {
    let Some(dir) = build_archive("ipsw-remote", &["--profile1"]) else {
        return;
    };
    let want = fs::read(dir.join("p1.payload")).unwrap();
    let pem = dir.join("p1-key.pem");
    let base = serve(dir.clone(), true);

    let listing = run(&["inspect", &format!("{base}/p1.ipsw"), "--json"]);
    assert!(
        listing.status.success(),
        "{}",
        String::from_utf8_lossy(&listing.stderr)
    );
    let v: Value = serde_json::from_slice(&listing.stdout).unwrap();
    assert_eq!(v["images"][0]["roles"][0], "os");

    for (url, pick, conns) in [
        (format!("{base}/p1.ipsw"), Some("os"), "4"),
        (format!("{base}/p1.ipsw"), Some("os"), "1"),
        (format!("{base}/p1.aea"), None, "3"),
    ] {
        let out = dir.join(format!("remote-{conns}.dmg"));
        let mut args = vec!["decrypt", &url];
        args.extend(pick);
        args.extend([
            "--key-pem",
            s(&pem),
            "-o",
            s(&out),
            "--connections",
            conns,
            "--json",
        ]);
        let o = run(&args);
        assert!(
            o.status.success(),
            "{url}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        assert!(fs::read(&out).unwrap() == want, "{url}: payload differs");
    }

    // Tampering fails the stream before the output appears: a segment,
    // or the padding (authenticated last of all).
    let aea = fs::read(dir.join("p1.aea")).unwrap();
    for (name, at) in [("seg", aea.len() / 2), ("pad", aea.len() - 1)] {
        let mut bad = aea.clone();
        bad[at] ^= 1;
        fs::write(dir.join(format!("bad-{name}.aea")), bad).unwrap();
        let out = dir.join(format!("bad-{name}.dmg"));
        let url = format!("{base}/bad-{name}.aea");
        assert_eq!(
            code(&["decrypt", &url, "--key-pem", s(&pem), "-o", s(&out)]),
            6,
            "{name}"
        );
        assert!(!out.exists(), "{name}: a failed decrypt leaves no output");
    }

    let out = dir.join("x.dmg");
    assert_eq!(
        code(&[
            "decrypt",
            &format!("{base}/p1.aea"),
            "--offline",
            "-o",
            s(&out)
        ]),
        2,
        "--offline refuses a URL"
    );
    assert_eq!(
        code(&["decrypt", &format!("{base}/missing.aea"), "-o", s(&out)]),
        3,
        "a URL that does not resolve is an unreadable input"
    );
    let no_ranges = serve(dir.clone(), false);
    assert_eq!(
        code(&[
            "decrypt",
            &format!("{no_ranges}/p1.aea"),
            "--key-pem",
            s(&pem),
            "-o",
            s(&out)
        ]),
        3,
        "a server without range requests"
    );
}

#[test]
fn key_urls_off_apple_hosts_are_not_fetched() {
    // The synthetic archive's key URL is on example.invalid: with no key
    // given, xaea refuses to fetch it (exit 7) rather than contacting it.
    let Some(dir) = build_archive("ipsw-keyhost", &["--profile1"]) else {
        return;
    };
    let o = run(&[
        "decrypt",
        s(&dir.join("p1.aea")),
        "-o",
        s(&dir.join("o.dmg")),
    ]);
    assert_eq!(o.status.code(), Some(7));
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("not an https URL on an Apple host"),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
}
