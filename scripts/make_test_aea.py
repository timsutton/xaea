#!/usr/bin/env python3 -I
"""Build a synthetic, fully signed profile-0 AEA + expected-tree manifest.

Everything the real extractor must handle is embedded on purpose:
multi-cluster geometry (spc=2, 3 clusters), the last-cluster capacity
padding erratum (1 real segment padded to 2 lists), a stored (uncompressed,
comp==orig) segment, a file whose blob spans clusters, a blob ending exactly
on a segment boundary, empty files, unicode + spaced + `..`-escape paths,
symlinks, non-default modes, and a self-signed P-256 signing certificate
whose key is bound into the main-key KDF info.

Usage: make_test_aea.py OUTPUT_DIR [--seed N]
Writes OUT/archive.aea and OUT/manifest.json.
"""
import argparse
import datetime
import hashlib
import hmac
import json
import lzma
import os
import struct
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID

S_IFDIR, S_IFREG, S_IFLNK = 0o040000, 0o100000, 0o120000
SEG = 65536          # segment size
SPC = 2              # segments per cluster (forces 3 clusters, padded last)
CAP = SPC


def mac(key: bytes, data: bytes, salt: bytes = b"") -> bytes:
    return hmac.new(key, salt + data + struct.pack("<Q", len(salt)),
                    hashlib.sha256).digest()


def hkdf(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                info=info).derive(ikm)


def prand(rng_state: bytes, n: int) -> bytes:
    """Deterministic pseudo-random bytes (hash counter)."""
    out = bytearray()
    c = int.from_bytes(rng_state[:8], "big")
    h = hashlib.sha512(rng_state)
    while len(out) < n:
        out += h.copy().digest()
        h.update(struct.pack("<Q", c))
        c += 1
    return bytes(out[:n])


def tag(key: str, fmt: str, payload: bytes) -> bytes:
    return key.encode() + fmt.encode() + payload


def u(n, v):  # little-endian uint of width n
    return int(v).to_bytes(n, "little")


def record(typ: str, path: str, mode: int, dat: int = 0,
           link: str | None = None) -> bytes:
    body = tag("TYP", "1", typ.encode())
    pb = path.encode()
    body += tag("PAT", "P", u(2, len(pb)) + pb)
    if link is not None:
        lb = link.encode()
        body += tag("LNK", "P", u(2, len(lb)) + lb)
    body += tag("UID", "1", u(1, 0)) + tag("GID", "1", u(1, 0))
    body += tag("MOD", "2", u(2, mode))
    if typ == "F" and dat:
        dfmt = "A" if dat < 65536 else "B"
        body += tag("DAT", dfmt, u(2 if dfmt == "A" else 4, dat))
        body += tag("FLG", "1", u(1, 0x20)) + tag("AFT", "1", u(1, 0x14))
    elif typ == "F":  # empty file: DAT absent (dat=0)
        body += tag("FLG", "1", u(1, 0x20)) + tag("AFT", "1", u(1, 0x14))
    return b"AA01" + u(2, 6 + len(body)) + body


def obj(type_: str, path: str, mode: int, content: bytes | None = None,
        link: str | None = None) -> dict:
    return {"t": type_, "path": path, "mode": mode, "content": content,
            "link": link}


def clamp(rel: str) -> str:
    """Mirror of Rust clamp(): '..' components pop, clamped at root."""
    out: list[str] = []
    for c in rel.split("/"):
        if c in ("", "."):
            continue
        if c == "..":
            if out:
                out.pop()
        else:
            out.append(c)
    return "/".join(out)


def build_tree(rng_state: bytes) -> tuple[list[dict], list[dict]]:
    """Returns (records in stream order, expected manifest entries)."""
    recs, expect = [], []

    def D(path, mode=0o755):
        recs.append(obj("D", path, S_IFDIR | mode))
        expect.append({"path": clamp(path), "t": "D", "mode": mode})

    def F(path, content, mode=0o644):
        recs.append(obj("F", path, S_IFREG | mode, content))
        expect.append({"path": clamp(path), "t": "F", "mode": mode,
                       "sha256": hashlib.sha256(content).hexdigest(),
                       "size": len(content)})

    def L(path, target, mode=0o777):
        recs.append(obj("L", path, S_IFLNK | mode, None, target))
        expect.append({"path": clamp(path), "t": "L", "target": target})

    D("T")
    D("T/sub dir")
    D("T/sub dir/ünïcode", 0o700)
    F("T/plain.txt", b"hello xcode\n" * 7)
    F("T/exec.sh", b"#!/bin/sh\necho hi\n", 0o755)
    F("T/sub dir/ünïcode/f.bin", prand(rng_state + b"uni", 5000))
    F("T/empty.bin", b"", 0o600)
    # Blob that spans multiple segments (and thus a cluster boundary).
    F("T/big.bin", prand(rng_state + b"big", SEG * 3 + 17))
    L("T/link-rel", "sub dir/ünïcode/f.bin")
    # Deliberate top-level escape: record path escapes above root twice;
    # extraction must clamp it to "escaped/inside.bin". The extractor
    # creates "escaped/" on demand (no D record for it) — expected below.
    D("esc")
    F("T/../../esc/../escaped/inside.bin", b"clamped\n")
    expect.append({"path": "escaped", "t": "D", "mode": 0o755})
    # Symlink whose *record* path stays inside but target escapes upward
    # (kept verbatim, like Apple's SharedFrameworks links).
    L("T/link-out", "../../../SystemFrameworks")
    return recs, expect


def pack_stream(recs: list[dict]) -> bytes:
    out = bytearray()
    for r in recs:
        body = record(r["t"], r["path"], r["mode"],
                      dat=len(r["content"]) if r["content"] else 0,
                      link=r["link"])
        out += body
        if r["content"]:
            out += r["content"]
    return bytes(out)


def align_boundary_file(recs: list[dict], rng_state: bytes) -> None:
    """Insert a file whose blob ends exactly on a segment boundary."""
    stream_len = len(pack_stream(recs))
    rec_len = len(record("F", "T/align.bin", S_IFREG | 0o644, dat=SEG))
    need = (SEG - (stream_len + rec_len) % SEG) % SEG
    dat = need + SEG  # at least SEG so it exercises DAT{B} too
    # Recompute with the chosen width (B for >65535 keeps rec_len fixed).
    rec_len2 = len(record("F", "T/align.bin", S_IFREG | 0o644, dat=dat))
    if rec_len2 != rec_len:
        dat += rec_len2 - rec_len
    recs.append(obj("F", "T/align.bin", S_IFREG | 0o644,
                    prand(rng_state + b"al", dat)))


def build(outdir: Path, seed: int) -> None:
    rng_state = hashlib.sha256(f"unaea-test-{seed}".encode()).digest()
    # Deterministic signing key (stable vectors for Rust unit tests).
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    d = int.from_bytes(prand(rng_state + b"ecdsa", 40), "big") % (order - 1) + 1
    key = ec.derive_private_key(d, ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                         "unaea synthetic test leaf")])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(0xC0FFEE)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256()))
    cert_pem = cert.public_bytes(
        serialization.Encoding.PEM).decode().encode()
    point = key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint)  # 65 B

    # --- payload stream ------------------------------------------------
    recs, expect = build_tree(rng_state)
    align_boundary_file(recs, rng_state)
    # Rebuild expectations for the appended align.bin.
    expect.append({"path": "T/align.bin", "t": "F", "mode": 0o644,
                   "sha256": hashlib.sha256(
                       recs[-1]["content"]).hexdigest(),
                   "size": len(recs[-1]["content"])})
    stream = pack_stream(recs)
    original_size = len(stream)

    # --- segmentation ---------------------------------------------------
    segs = [stream[i:i + SEG] for i in range(0, len(stream), SEG)]
    comp_segs, cksums = [], []
    for idx, s in enumerate(segs):
        cksums.append(hashlib.sha256(s).hexdigest())
        if idx == 1:  # stored segment (comp == orig, no xz)
            comp_segs.append(s)
        else:
            comp_segs.append(lzma.compress(s, format=lzma.FORMAT_XZ))
    nsegs = len(segs)

    # --- keys -----------------------------------------------------------
    ikm = prand(rng_state + b"ikm", 32)
    mainsalt = prand(rng_state + b"salt", 32)
    mainkey = hkdf(ikm, mainsalt, b"AEA_AMK" + b"\x00\x00\x00\x00" + point)
    rootkey = hkdf(mainkey, b"", b"AEA_RHEK")

    # --- auth data -------------------------------------------------------
    # Auth entries: [u32 len-including-self][key NUL value-bytes]  (erratum 1)
    key1 = b"com.apple.ias.signature.certificate-chain"
    pairs = [(key1, cert_pem)]
    auth = b"".join(
        u(4, 4 + 1 + len(k) + len(v)) + k + b"\x00" + v for k, v in pairs
    )

    # --- geometry constants ---------------------------------------------
    hdr_len = 12 + len(auth) + 128 + 32 + 32 + 32 + 48 + 32  # to chmac0
    chmac_off = 12 + len(auth) + 128 + 32 + 32 + 32 + 48
    nclusters = -(-nsegs // SPC)
    clusters_data = []
    for k in range(nclusters):
        lo, hi = k * SPC, min((k + 1) * SPC, nsegs)
        clusters_data.append(sum(len(comp_segs[i]) for i in range(lo, hi)))
    total = hdr_len + sum(CAP * 40 + 32 + CAP * 32 + d
                          for d in clusters_data)

    roothdr = struct.pack("<QQII", original_size, total, SEG, SPC) \
        + b"x" + b"\x02" + b"\x00" * 22
    assert len(roothdr) == 48

    # --- clusters, chmac chain (compute backwards) ------------------------
    cluster_blobs = [b""] * nclusters
    chmac = b"\x00" * 32  # next-chmac for the last cluster: zeros
    for k in reversed(range(nclusters)):
        lo, hi = k * SPC, min((k + 1) * SPC, nsegs)
        ck = hkdf(mainkey, b"", b"AEA_CK" + u(4, k))
        chek = hkdf(ck, b"", b"AEA_CHEK")
        segkeys = [hkdf(ck, b"", b"AEA_SK" + u(4, i))
                   for i in range(hi - lo)]
        seghdrs = b"".join(
            u(4, len(segs[i])) + u(4, len(comp_segs[i]))
            + bytes.fromhex(cksums[i])
            for i in range(lo, hi))
        seghdrs += b"\x00" * (CAP - (hi - lo)) * 40  # erratum 2 padding
        seghmacs = b"".join(
            mac(segkeys[i - lo], comp_segs[i], b"") for i in range(lo, hi))
        seghmacs += b"\x00" * (CAP - (hi - lo)) * 32
        chmac_k = mac(chek, seghdrs, chmac + seghmacs)
        data = b"".join(comp_segs[i] for i in range(lo, hi))
        cluster_blobs[k] = seghdrs + chmac + seghmacs + data
        chmac = chmac_k
    chmac0 = chmac

    rootmac = mac(rootkey, roothdr, chmac0 + auth)

    # --- assemble + sign ---------------------------------------------------
    file = bytearray()
    file += b"AEA1" + b"\x00\x00\x00\x00" + u(4, len(auth)) + auth
    sig_off = len(file)
    file += b"\x00" * 128
    file += ikm + mainsalt + rootmac + roothdr + chmac0
    for b in cluster_blobs:
        file += b
    assert len(file) == total, f"size {len(file)} != {total}"
    prefix = bytes(file[:chmac_off + 32])  # sig field already zeroed
    der = key.sign(prefix, ec.ECDSA(hashes.SHA256()))  # cryptography >= 49: (data, alg)
    file[sig_off:sig_off + len(der)] = der

    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "archive.aea").write_bytes(bytes(file))

    by_path = {clamp(r["path"]): r["content"] for r in recs if r["t"] == "F"}
    for e in expect:
        if e["t"] == "F":
            e["hex"] = by_path[e["path"]].hex()
    manifest = {
        # entries expected on disk (includes implicit dirs) vs record counts
        # (what the extractor's stats must report).
        "counts": {"D": sum(1 for e in expect if e["t"] == "D"),
                   "F": sum(1 for e in expect if e["t"] == "F"),
                   "L": sum(1 for e in expect if e["t"] == "L")},
        "stats": {"dirs": sum(1 for r in recs if r["t"] == "D"),
                  "files": sum(1 for r in recs if r["t"] == "F"),
                  "links": sum(1 for r in recs if r["t"] == "L")},
        "entries": expect,
        "original_size": original_size,
        "segments": nsegs,
        # KDF vectors for src/kdf.rs unit tests.
        "vectors": {
            "ikm": ikm.hex(), "mainsalt": mainsalt.hex(),
            "point": point.hex(),
            "mainkey": mainkey.hex(),
            "rootkey": rootkey.hex(),
            "ck0": hkdf(mainkey, b"", b"AEA_CK" + u(4, 0)).hex(),
            "chek0": hkdf(hkdf(mainkey, b"", b"AEA_CK" + u(4, 0)),
                          b"", b"AEA_CHEK").hex(),
            "segment0key": hkdf(hkdf(mainkey, b"", b"AEA_CK" + u(4, 0)),
                                b"", b"AEA_SK" + u(4, 0)).hex(),
        },
    }
    (outdir / "manifest.json").write_text(json.dumps(manifest, indent=1))
    print(f"archive.aea: {total} bytes, {nsegs} segments, "
          f"{original_size} payload bytes, {len(expect)} manifest entries")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir", type=Path)
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    build(a.outdir, a.seed)
