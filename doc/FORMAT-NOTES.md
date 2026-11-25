# AEA format notes — verified against Apple's Xcode 27.3 beta 2 artifact

Everything here was confirmed empirically against
`fixtures/Xcode_27.3_beta_2.aea` (2,174,613,438 B, profile 0). The primary
reference is [kinnay's FORMAT.md](https://github.com/kinnay/AEA/blob/main/FORMAT.md);
this file records where reality deviates from it, plus the details the spec
leaves open. The Apple Wiki's "Apple Encrypted Archive" page describes a
different (Swift-serialized/GCM) layout that matches nothing in this file —
ignore it for this variant.

## File layout (all integers LE)

```
0    "AEA1"
4    profile: 3 bytes + byte[7] (scrypt strength; 0 here)
8    u32 auth_data_size                     (counts what follows; = 3802)
12   auth data: repeated (u32 len, key NUL value)
     ^ erratum 1: each u32 length prefix INCLUDES its own 4 bytes, and the
     key and value share one entry as `key\0value` (the spec's "two length
     prefixes" reading parses nothing real)
     here: key "com.apple.ias.signature.certificate-chain" -> 3-cert PEM
12+auth_size
     128 B signature  (DER ECDSA P-256, null-padded to 128)
     32 B  public key section (profile 0: random 32-byte IKM)
     32 B  main salt
     32 B  root header MAC
     48 B  root header (plaintext for profile 0), tail 22 B zeros
     32 B  first cluster header MAC (chmac[0])
     clusters...
```

Root header fields: `u64 original_size, u64 encarchive_size, u32 segment_size,
u32 segments_per_cluster, u8 compression, u8 checksum` + 22 B zero tail.
Fixture: original 10,464,202,071; encarchive 2,174,613,438 (== file size —
the `encarchive_size` check is a complete-download test); segments 16 MiB;
256 segments/cluster; compression `'x'` = **standalone .xz container per
segment** (LZMA2; `liblzma`/`xz -d` decode each segment independently);
checksum 2 = SHA-256.

## Cluster geometry

Cluster k at offset C, with `cap = segments_per_cluster`, header entry =
`u32 orig + u32 comp + 32B checksum` (40 B for checksum=2):

```
C                              segment-header list, cap entries
C + cap*40                     next cluster's chmac (32 B; garbage beyond last)
C + cap*40 + 32                segment-MAC list, cap entries
C + cap*72 + 32                segment data (concatenated comp bytes)
```

**Erratum 2:** the *last* cluster's header and MAC lists are still padded to
the **full** `cap` entries (fixture: 112 real segments in 256-wide lists).
A walk that uses the real segment count for list sizes misses exactly
`(cap - n) * 72` bytes and fails to land on EOF.

## Key derivation (HKDF-SHA256; salt empty except main key)

`mac(key, data, salt) = HMAC-SHA256(key, salt || data || u64le(len(salt)))`.

- main key: IKM = pubkey section, salt = main salt,
  info = `"AEA_AMK" || file[4..8] || <uncompressed P-256 point (65 B) of the
  signing certificate's public key>` — the signing-key-in-info part is only
  implied by the spec's "if the profile uses signing" note; confirmed by the
  root MAC matching.
- root header key: info `"AEA_RHEK"`; root MAC =
  `mac(rootkey, roothdr48, chmac[0] || auth_data)`.
- cluster key k: info `"AEA_CK" || u32le(k)`; cluster header key: `"AEA_CHEK"`.
- segment key: info `"AEA_SK" || u32le(cluster-local index)` — see erratum 4.
  (Key unused for profile 0 — payload is stored *compressed, not encrypted*;
  only the MAC uses it.)

## Cluster header MAC (spec is vague — this is what Apple does)

`chmac[k] = mac(cluster_header_key(k), SEGHDRS_PADDED, SALT_PADDED)` where

- `SEGHDRS_PADDED` = the cluster's segment-header list padded to `cap`
  entries (erratum 2 applies to full clusters trivially), and
- `SALT_PADDED` = `next-chmac(32 B) || segment-MAC list padded to cap`.

chmac[0] lives before cluster 0; chmac[k+1] lives inside cluster k. Verified
for all 3 clusters of the fixture.

## Segment checksums — erratum 3

Segment `cksum` is SHA-256 of the **decompressed** segment bytes (verified:
`sha256(xz_decode(data)) == cksum` for all 624 segments; hashing the stored
compressed bytes matches nothing). Also `orig == len(xz_decode(data))`.

## Segment MACs

Profile 0 stores no encryption, but each segment still has a 32-byte MAC in
the cluster's MAC list: `mac(segment_key, <stored segment bytes>, b"")` with
`segment_key = HKDF(cluster_key, "", "AEA_SK" || u32le(CLUSTER-LOCAL index))`
— **erratum 4: the local index, not the global one** (global fails from
cluster 1 on; verified over all 624 segments). Empty salt; data = stored
(compressed) bytes — note the asymmetry: checksums cover the decompressed
domain, MACs the compressed one.

## File signature

ECDSA P-256 over SHA-256 of `file[0 .. chmac0_offset + 32)` with the 128-byte
signature field zeroed (matches kinnay's spec exactly; verified against the
leaf cert in the auth chain). The chain: leaf (per-artifact IAS identity,
P-256) ← `Apple Platform Signing ECC CA 1 - G1` (P-384) ←
`Apple Root CA - G3` (P-384, self-signed; vendored in `assets/AppleRootCA.pem`).
Leaf cert's SPKI point doubles as the KDF info binding (see main key above),
so the root MAC check already proves key ↔ file binding.

## DER/pem gotchas that bit us twice

- OIDs: `1.2.840.10045.*` base-128 encodes 10045 as `CE 3D` (**not** `CC 3D`).
- ECDSA signatures cover the *full* DER TLV of the signed ASN.1 structure
  (tag + length prefix included), not the SEQUENCE content.
- A hand-rolled base64 decoder must emit partial trailing chunks from the
  **top** of the accumulator (`KA==` -> `0x28`, not `0x80`).

## Payload — the AA01 object stream (M2, fully decoded)

Concatenated decompressed segments form ONE `AA01` Apple Archive object
stream. Records: `"AA01" + u16le size` (size includes the 6-byte header),
body = 4-byte tagged fields `TAG<F>` where `<F>` encodes the payload kind:
`1/2/4/8` = LE int of that width; `A/B/C` = LE int of width 2/4/8;
`P` = u16le length + bytes; `p` = u32le length + bytes.

Observed tags (fixture: 30,082 D / 126,205 F / 11,254 L records):
- `TYP{1}`: object type — `D`ir / `F`ile / `L`ink.
- `PAT{P}` path; `LNK{P}` link target (relative, may escape via `../` —
  clamp like unxip; the escape target never lands in the archive).
- `UID{1}` `GID{1}` (all 0/0 here), `MOD{2}` full st_mode incl S_IF bits.
- `DAT{A|B}` = inline data length (2- or 4-byte width tier). A file record is
  immediately followed by its DAT bytes in the stream (not counted in the
  record size); files span segment boundaries freely.
- `FLG{1}`(=0x20) `AFT{1}`(=0x14) seen only on file records, constant values.

Extraction fidelity proven by: 624/624 segment checksums (payload is
Apple's bytes), exhaustive record walk (framing exact), 100% path-set match
vs `unxip` output of the same-version .xip, and `codesign --deep --strict`
passing on the whole extracted app. (The .aea/.xip builds differ in 2,002
Mach-O CMS signature blobs — Apple re-signed for the AEA distribution.)

## On-disk output: what `archiveutil` writes (transparent compression)

Apple's `archiveutil extractXcodeAEA` doesn't write plain files. It stores
almost every file with APFS transparent compression (decmpfs), so the
9.71 GiB Xcode 27.3 b2 payload takes **3.86 GiB** on disk (`du -sk`:
4,049,568 KiB). Surveyed over its full output tree (`UF_COMPRESSED` flag +
the `com.apple.decmpfs` xattr, read with `XATTR_SHOWCOMPRESSION`):

| layout | files | notes |
|---|---|---|
| decmpfs **type 13** (LZBITMAP, inline in the xattr) | 88,006 | whole file in the xattr, no data blocks |
| decmpfs **type 14** (LZBITMAP, resource fork) | 37,881 | 64 KiB chunks |
| plain | 318 | 1 empty file plus files that don't shrink by a block (`.pkg`, `.car`, PNGs): 718 MB |

The details below were all checked against that tree and by writing files
by hand and reading them back through the kernel (`src/decmpfs.rs`):

* `com.apple.decmpfs` starts with a 16-byte header: `"fpmc"`, u32 type,
  u64 uncompressed size (LE).
* **LZBITMAP** is libcompression's `COMPRESSION_LZBITMAP` (0x702, public
  since macOS 12). Each encoded chunk is a raw `compression_encode_buffer`
  stream (`"ZBM\x09"…`). It encodes ~350 MB/s per M3 Max core, about 2×
  LZFSE (164 MB/s), for a slightly worse ratio (31.7% vs 28.6% on IDEKit).
* **Type 14 fork** (`com.apple.ResourceFork`): `n + 1` u32 LE offsets
  (from the fork start; the last one is the fork length), then the `n`
  chunks, each encoding 64 KiB of the file (the last one shorter). This is
  the same scheme as LZVN/LZFSE types 8/12.
* **Uncompressible chunk**: `0xFF` followed by the raw bytes (a full one is
  65,537 bytes). LZBITMAP's own fallback (+22 bytes) also decodes fine, but
  `0xFF` is what Apple writes.
* **Type 13 inline**: header + one chunk (encoded, or `0xFF` + raw), used
  when it fits in **3,584 bytes** total. Apple's largest inline xattr is
  exactly 3,584 bytes and its smallest type-14 chunk would have made 3,598.
  So every file of ≤ 3,567 bytes ends up inline, even raw, and costs no
  data blocks.
* Write order: fork, then decmpfs xattr, then `fchflags(UF_COMPRESSED)`.
  Until the flag is set the file reads as empty (the data fork stays at
  length 0). The fork has to be written in one `fsetxattr`: positional
  chunk-by-chunk writes worked but allocated ~2× the blocks.
* **Gotcha:** the kernel checks xattr writes against the *file's mode*, not
  the fd's open mode, so a 0444 file refuses `fsetxattr` with EACCES even on
  a writable fd. Apply the mode after storing.

## Profile 1: restore-image disk images

iOS and macOS restore images (IPSWs, e.g. `iPhone17,3_27.2.1_24B156` and
`UniversalMac_27.2.1_26B131`) ship their large disk images as
`<part>.dmg.aea`, stored uncompressed in the IPSW zip. They are profile 1,
`hkdf_sha256_aesctr_hmac__symmetric__none`. Everything below was verified
against two of them (248 MiB with 1 cluster, and 2.25 GiB with 24 clusters)
and checked against `aea decrypt` from both directions. xaea's output is
byte-identical to Apple's, and Apple's tool accepts the synthetic archive
that `scripts/make_test_aea.py --profile1` builds when the builder uses
Apple's geometry. (`aea` refuses the builder's default of 2 segments per
cluster; the format allows it.)

### Differences from profile 0

* **No signature, no key section.** The 32-byte main salt follows the auth
  data directly.
* **Main key:** IKM = the 32-byte symmetric key, salt = the main salt,
  info = `"AEA_AMK" || file[4..8]` (no signing key).
* **80-byte keys.** The root-header (`AEA_RHEK`), cluster-header (`AEA_CHEK`)
  and segment (`AEA_SK` || u32le local index) keys are HKDF-expanded to 80
  bytes: `MAC key (32) || AES-256 key (32) || CTR IV (16)`. HKDF output is a
  prefix stream, so the MAC third equals the 32-byte key profile 0 derives
  from the same info. The counter is AES-256-CTR, a 128-bit big-endian
  counter starting at the IV.
* **Encrypt-then-MAC.** The root header, each cluster's segment-header list
  (padded to capacity, as in profile 0) and each segment's stored bytes are
  encrypted. Every MAC covers the ciphertext with the same layouts as
  profile 0. Segment checksums are still SHA-256 of the decompressed
  plaintext. Check the root MAC before decrypting: a wrong key fails there.
* **Compression:** `e` = LZFSE, one raw `bvx2` stream per segment, in 1 MiB
  segments with 256 per cluster. The payload is itself a compressed UDIF DMG
  or a raw APFS image, so most segments are stored (comp == orig).
* **The payload is a disk image,** not an AA01 stream.

### Padding (not in kinnay's spec)

`encarchive_size` (= file size, a MiB multiple) leaves random padding after
the last segment: 4.0 MiB and 38.7 MiB on the two archives. It is
authenticated: the last cluster's next-cluster-MAC slot holds

    HMAC-SHA256(HKDF(main_key, "", "AEA_PAK"), padding)

This is a **plain** HMAC, without the `salt || data || u64le(len(salt))`
framing of every other MAC. Found by probing `aea encrypt -padding 16|64k`
output; with `-padding none` the slot is filled but not checked (as with
profile 0's "garbage" last slot). `aea decrypt` rejects a wrong padding MAC
("authenticating padding").

### The key: WKMS auth data

| auth key | value |
|---|---|
| `com.apple.wkms.fcs-response` | JSON: base64 `enc-request` (65-byte P-256 point), `wrapped-key` (32 + 16 bytes) |
| `com.apple.wkms.fcs-key-url` | `https://wkms-public.apple.com/fcs-keys/<id>` → 301 to a CDN; an unauthenticated PKCS#8 P-256 private-key PEM |
| `com.apple.wkms.url`, `com.apple.wkms.auth-data`, `saksKey` | the online key-service request; unused offline |

The wrap is RFC 9180 HPKE in base mode, DHKEM(P-256, HKDF-SHA256) /
HKDF-SHA256 / AES-256-GCM, with empty `info` and AAD. `<id>` is
`base64url(SHA-256(uncompressed public point))` of the PEM's key, so a PEM
can be matched to its archive offline. One PEM served every archive in the
IPSW we checked.
