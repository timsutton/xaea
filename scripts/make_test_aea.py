#!/usr/bin/env python3 -I
"""Build a synthetic, fully signed profile-0 AEA + expected-tree manifest.

Everything the real extractor must handle is embedded on purpose:
multi-cluster geometry (spc=2, 4 clusters), the last-cluster capacity
padding erratum (1 real segment padded to 2 lists), a stored (uncompressed,
comp==orig) segment, a file whose blob spans clusters, a blob ending exactly
on a segment boundary, empty files, unicode + spaced + `..`-escape paths,
symlinks, non-default modes, and a self-signed P-256 signing certificate
whose key is bound into the main-key KDF info.

Usage: python3 -I scripts/make_test_aea.py OUTPUT_DIR [--seed N] [--evil]
       [--links N] [--tamper]
Writes OUT/archive.aea and OUT/manifest.json. See tests/fixtures/README.md
for the checked-in fixture set.
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
SPC = 2              # segments per cluster (forces 4 clusters, padded last)
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

    def F(path, content, mode=0o644, expect_mode=None):
        recs.append(obj("F", path, S_IFREG | mode, content))
        expect.append({"path": clamp(path), "t": "F",
                       "mode": mode if expect_mode is None else expect_mode,
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
    # setuid bit present in the record; extraction must strip it (the
    # manifest records the expected ON-DISK mode).
    F("T/setuid.bin", b"setuid-me\n", 0o4755, expect_mode=0o755)
    # Read-only files: with --compress the xattrs must be written before
    # the mode is applied (the kernel checks xattr writes against the mode).
    # One fits inline in the decmpfs xattr, one needs a multi-chunk fork.
    F("T/readonly.txt", b"read me\n" * 50, 0o444)
    F("T/readonly-big.txt", b"".join(b"line %d of a compressible file\n" % i
                                     for i in range(5000)), 0o444)
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


def make_signer(rng_state: bytes):
    """Derive a signing key from the seed and issue a self-signed leaf."""
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    d = int.from_bytes(prand(rng_state + b"ecdsa", 40), "big") % (order - 1) + 1
    key = ec.derive_private_key(d, ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                         "xaea synthetic test leaf")])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(0xC0FFEE)
            # The extractor checks validity against the current time.
            .not_valid_before(datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2099, 12, 31, tzinfo=datetime.timezone.utc))
            .sign(key, hashes.SHA256()))
    cert_pem = cert.public_bytes(
        serialization.Encoding.PEM).decode().encode()
    point = key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint)  # 65 B
    return key, cert_pem, point


def assemble(stream: bytes, rng_state: bytes, key, cert_pem, point,
             out_path: Path) -> dict:
    """Segment, key, MAC-chain, sign and write a signed profile-0 AEA."""
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

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(file))
    return {"total": total, "nsegs": nsegs, "original_size": original_size,
            "ikm": ikm, "mainsalt": mainsalt, "mainkey": mainkey,
            "rootkey": rootkey}


def build(outdir: Path, seed: int) -> None:
    rng_state = hashlib.sha256(f"xaea-test-{seed}".encode()).digest()
    key, cert_pem, point = make_signer(rng_state)

    recs, expect = build_tree(rng_state)
    align_boundary_file(recs, rng_state)
    # Rebuild expectations for the appended align.bin.
    expect.append({"path": "T/align.bin", "t": "F", "mode": 0o644,
                   "sha256": hashlib.sha256(
                       recs[-1]["content"]).hexdigest(),
                   "size": len(recs[-1]["content"])})
    info = assemble(pack_stream(recs), rng_state, key, cert_pem, point,
                    outdir / "archive.aea")

    by_path = {clamp(r["path"]): r["content"] for r in recs if r["t"] == "F"}
    for e in expect:
        if e["t"] == "F":
            e["hex"] = by_path[e["path"]].hex()
    mainkey, ikm, mainsalt, rootkey = (
        info["mainkey"], info["ikm"], info["mainsalt"], info["rootkey"])
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
        "original_size": info["original_size"],
        "segments": info["nsegs"],
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
    print(f"archive.aea: {info['total']} bytes, {info['nsegs']} segments, "
          f"{info['original_size']} payload bytes, {len(expect)} manifest entries")


def build_evil(outdir: Path, seed: int) -> None:
    """Three adversarial archives; a safe extractor must fail all of them, and
    any partial writes must stay inside the output tree."""
    rng_state = hashlib.sha256(f"xaea-test-{seed}-evil".encode()).digest()
    key, cert_pem, point = make_signer(rng_state)
    # evil1: tar-style link attack — symlink `app/up -> ..` plus a file
    # record whose path passes through it. Naive extractors write
    # PWNED next to (outside) the output tree.
    recs1 = [obj("D", "app", S_IFDIR | 0o755),
             obj("L", "app/up", S_IFLNK | 0o777, None, ".."),
             obj("F", "app/up/PWNED", S_IFREG | 0o644, b"esc\n")]
    assemble(pack_stream(recs1), rng_state, key, cert_pem, point,
             outdir / "evil1.aea")
    # evil2: a symlink record whose path traverses an earlier symlink.
    recs2 = [obj("L", "l1", S_IFLNK | 0o777, None, ".."),
             obj("L", "l1/l2", S_IFLNK | 0x1ff, None, "tmp")]
    assemble(pack_stream(recs2), rng_state, key, cert_pem, point,
             outdir / "evil2.aea")
    # evil3: the same traversal, spelled with capitals. The guard compares a
    # lowercased ancestor against the set of links created so far; a
    # comparison that forgot to lowercase one side (the regression this
    # archive guards against) let `Payload/up/under` be created straight
    # through `Payload/up` and out of the tree.
    recs3 = [obj("L", "Payload/up", S_IFLNK | 0o777, None, ".."),
             obj("L", "Payload/up/under", S_IFLNK | 0o777, None, "tmp")]
    assemble(pack_stream(recs3), rng_state, key, cert_pem, point,
             outdir / "evil3.aea")


def build_links(outdir: Path, seed: int, n: int) -> None:
    """Archive that exercises the final symlink pass at scale.

    `n` links spread over a framework-shaped tree whose directories already
    exist — what a real archive looks like, where the pass is pure symlink(2)
    work — plus the shapes the pass special-cases: a link whose parent
    directory has no record at all (mkdir -p fallback), a link whose name is
    already occupied by a regular file (replace, not refuse), and unicode /
    space names. No link is nested under another, so the list qualifies for
    the concurrent path. Writes links.aea and links-manifest.json.
    """
    rng_state = hashlib.sha256(f"xaea-test-{seed}-links".encode()).digest()
    key, cert_pem, point = make_signer(rng_state)
    ndirs = max(1, min(n, 200))
    recs, expect = [], []
    for d in range(ndirs):
        recs.append(obj("D", f"P/F/{d:04}/N.framework/Versions", S_IFDIR | 0o755))
    # A regular file occupying a name a later link record wants.
    recs.append(obj("F", "P/F/0000/occupied", S_IFREG | 0o644, b"occupant\n"))
    for i in range(n):
        d = i % ndirs
        if i % 7 == 2:
            # No D record anywhere under "orphan": the pass must create it.
            path = f"orphan/{i % 20:02d}/missing/parent/l{i}"
        elif i % 7 == 3:
            path = f"P/F/{d:04}/N.framework/Versions/ünïcode l{i}"
        elif i % 7 == 4:
            path = f"P/F/{d:04}/N.framework/Versions/sp ace/l{i}"
        else:
            path = f"P/F/{d:04}/N.framework/Versions/l{i}"
        recs.append(obj("L", path, S_IFLNK | 0o777, None, f"../../tgt/{i}"))
        expect.append({"path": path, "target": f"../../tgt/{i}"})
    recs.append(obj("L", "P/F/0000/occupied", S_IFLNK | 0o777, None,
                    "now-a-link"))
    expect.append({"path": "P/F/0000/occupied", "target": "now-a-link"})
    assemble(pack_stream(recs), rng_state, key, cert_pem, point,
             outdir / "links.aea")
    (outdir / "links-manifest.json").write_text(
        json.dumps({"links": expect}, indent=1))
    print(f"links.aea: {len(expect)} link records")


def sig_field_span(file: bytes) -> tuple[int, int]:
    """(sig_off, der_end) of the signature field in a built archive."""
    assert file[:4] == b"AEA1", "not an AEA1 archive"
    sig_off = 12 + int.from_bytes(file[8:12], "little")
    field = file[sig_off:sig_off + 128]
    assert field[0] == 0x30, "signature field does not open a DER SEQUENCE"
    assert field[1] < 0x80, "unexpected long-form DER length in sig field"
    der_end = sig_off + 2 + field[1]
    assert field[2 + field[1]:] == b"\x00" * (128 - 2 - field[1]), \
        "signature field is not zero-padded"
    return sig_off, der_end


def build_tamper(outdir: Path, seed: int) -> None:
    """Corrupt variants of the signed archive, one per rejection path.

    Each must be refused by `extract` (before anything is written) and by
    `inspect --verify`, with a message naming the failure mode. The
    expectations live in tamper.json so the Rust test stays a plain table
    walk: `name` the file, `mode` what is broken, `expect` substrings that
    must appear in stderr (lowercased), `check_false`/`check_true` the
    `inspect --verify --json` checks that must be false/true, and `parses`
    whether the envelope is still structurally parseable at all.
    """
    src = (outdir / "archive.aea").read_bytes()
    sig_off, der_end = sig_field_span(src)
    cases = []

    def emit(name, data, mode, expect, check_false=(), check_true=(),
             parses=True):
        if data is not None:
            (outdir / name).write_bytes(bytes(data))
        cases.append({"name": name, "mode": mode, "expect": list(expect),
                      "check_false": list(check_false),
                      "check_true": list(check_true), "parses": parses})

    def flip(pos, value=None):
        b = bytearray(src)
        b[pos] = (src[pos] ^ 0x01) if value is None else value
        return b

    # 1) Well-formed DER, wrong signature value: flip the low bit of the
    #    last byte of INTEGER s. Structure, length and zero padding all stay
    #    intact, so this is purely the ECDSA verify-prehash path.
    emit("bad-sig.aea", flip(der_end - 1),
         "signature bytes do not match the signed prefix",
         ["signature"], ["content_signature_ok"], ["signature_padded_ok"])

    # 2) Signature that opens no DER SEQUENCE: the tag is zeroed. The field
    #    still has a sane length, so it stays reportable — the signature
    #    fails, the padding check does not.
    emit("bad-sig-der.aea", flip(sig_off, 0x00),
         "signature field opens no DER SEQUENCE",
         ["signature"], ["content_signature_ok"], ["signature_padded_ok"])

    # 3) Malformed signature length: the SEQUENCE claims 127 bytes inside a
    #    128-byte field, so the DER runs past it. A bad length here must
    #    stay a failed check, never a panic or a fatal parse error.
    emit("bad-sig-len.aea", flip(sig_off + 1, 0x7F),
         "signature DER length runs past the field",
         ["signature"], ["content_signature_ok", "signature_padded_ok"])

    # 4) Genuinely valid signature, dirty zero padding after it: only the
    #    padding check may fire.
    emit("bad-padding.aea", flip(der_end, 0xFF),
         "non-zero padding after the signature",
         ["padding"], ["signature_padded_ok"], ["content_signature_ok"])

    # 5) Truncated envelope: the last 4 KiB are gone, so the cluster walk
    #    runs past EOF. Different path entirely (src/envelope.rs), and no
    #    report is produced because parsing fails before any check runs.
    emit("truncated.aea", src[:-4096], "archive truncated mid-cluster",
         ["truncated"], parses=False)

    # 6) Chain whose leaf was not signed by its stated issuer: a second,
    #    unrelated self-signed certificate is appended to the chain. The
    #    content signature stays valid (the leaf key still signs the
    #    prefix), so only chain policy can reject this one.
    rng = hashlib.sha256(f"xaea-test-{seed}-chain".encode()).digest()
    key, leaf_pem, point = make_signer(rng)
    _, other_pem, _ = make_signer(rng + b"-issuer")
    recs = [obj("D", "app", S_IFDIR | 0o755),
            obj("F", "app/a.txt", S_IFREG | 0o644, b"chain mismatch\n")]
    assemble(pack_stream(recs), rng, key, leaf_pem + other_pem, point,
             outdir / "chain-mismatch.aea")
    emit("chain-mismatch.aea", None,
         "certificate chain link does not verify",
         ["chain"], ["chain_all_ok"], ["content_signature_ok"])

    (outdir / "tamper.json").write_text(json.dumps({"cases": cases}, indent=1))
    print(f"tamper: {len(cases)} corrupt variants written")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir", type=Path)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--evil", action="store_true",
                    help="also build evil1/evil2/evil3.aea link-attack archives")
    ap.add_argument("--links", type=int, default=0, metavar="N",
                    help="also build links.aea with N link records")
    ap.add_argument("--tamper", action="store_true",
                    help="also build corrupt-signature variants + tamper.json")
    a = ap.parse_args()
    build(a.outdir, a.seed)
    if a.evil:
        build_evil(a.outdir, a.seed)
    if a.links:
        build_links(a.outdir, a.seed, a.links)
    if a.tamper:
        build_tamper(a.outdir, a.seed)
