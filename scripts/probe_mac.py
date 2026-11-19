#!/usr/bin/env python3 -I
"""Brute-force probe: last-cluster chmac domain/salt + content signature domain."""
import hashlib, hmac, struct, base64, sys

PATH = "fixtures/Xcode_27.3_beta_2.aea"
f = open(PATH, "rb").read()

def hkdf(ikm, salt, info, n=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:n]

def mac(key, data, salt):
    m = hmac.new(key, b"", hashlib.sha256)
    m.update(salt); m.update(data)
    m.update(struct.pack("<Q", len(salt)))
    return m.digest()

auth_size = struct.unpack_from("<I", f, 8)[0]
auth_start, auth_end = 12, 12 + auth_size
sig_off = auth_end
pubkey_off = sig_off + 128
mainsalt_off = pubkey_off + 32
rootmac_off = mainsalt_off + 32
root_off = rootmac_off + 32
chmac_off = root_off + 0x30

# leaf point from chain pem
pem = open("assets/signing-chain.pem", "rb").read()
certs, cur = [], None
for line in pem.split(b"\n"):
    if b"BEGIN" in line: cur = []
    elif b"END" in line: certs.append(base64.b64decode(b"".join(cur))); cur = None
    elif cur is not None: cur.append(line)
leaf = certs[0]
i = leaf.find(b"\x03\x42\x00\x04")
point = leaf[i+3:i+3+65]
assert len(point) == 65

main = hkdf(f[pubkey_off:pubkey_off+32], f[mainsalt_off:mainsalt_off+32],
            b"AEA_AMK" + f[4:8] + point)

spc = struct.unpack_from("<I", f, root_off + 20)[0]
seg_hdr_len = 40
# walk clusters
offs = []
cur = chmac_off + 32
segs_total = 0
while cur < len(f):
    offs.append(cur)
    n = 0
    doff = cur + spc*seg_hdr_len + 32 + spc*32
    # count segments until next cluster boundary: we know actual segment counts 256/256/112
    offs.append(doff)  # placeholder
    break
# simpler: derive counts from known totals; recompute properly:
cluster_offs = []
d = chmac_off + 32
counts = []
while d < len(f):
    cluster_offs.append(d)
    # try to read segment headers from d; segment data starts after padded lists
    data_start = d + spc*seg_hdr_len + 32 + spc*32
    # count segments: read headers until data region... we don't know count directly.
    # Use the property: segments of a cluster are contiguous; last cluster count solved by file end.
    counts.append(None)
    d = None
    break
# brute counts: for cluster k, sum(comp)+hdrs == file end. Compute iteratively per cluster by
# scanning: total segments = ceil(original/segsize)? original from root header:
orig, encarch, segsize = struct.unpack_from("<QQI", f, root_off)
nsegs = (orig + segsize - 1) // segsize
rem = nsegs
print("nsegs", nsegs, "spc", spc)

def cluster_walk():
    d = chmac_off + 32
    cl = []
    left = nsegs
    while left:
        n = min(spc, left)
        hdrs = d
        data_start = d + spc*seg_hdr_len + 32 + spc*32
        comp = 0
        for s in range(n):
            o, c = struct.unpack_from("<II", f, hdrs + s*seg_hdr_len)
            comp += c
        cl.append((hdrs, n))
        d = data_start + comp
        left -= n
    assert d == len(f), (d, len(f))
    return cl

clusters = cluster_walk()
print("clusters:", [(h, n) for h, n in clusters])

# stored chmacs: chmac_off = chmac[0]; cluster k stores chmac[k+1] at hdrs+spc*40
chmac0 = f[chmac_off:chmac_off+32]
def stored_chmac(k):
    if k == 0: return chmac0
    prev_h, prev_n = clusters[k-1]
    off = prev_h + spc*seg_hdr_len
    return f[off:off+32]

# ---- probe last cluster ----
k = len(clusters)-1
h, n = clusters[k]
ck = hkdf(main, b"", b"AEA_CK" + struct.pack("<I", k))
chek = hkdf(ck, b"", b"AEA_CHEK")
stored = stored_chmac(k)
nextchmac = f[h + spc*seg_hdr_len : h + spc*seg_hdr_len + 32]
seghdrs_act = f[h : h + n*seg_hdr_len]
seghdrs_pad = f[h : h + spc*seg_hdr_len]
seghmacs_act = f[h + spc*seg_hdr_len + 32 : h + spc*seg_hdr_len + 32 + n*32]
seghmacs_pad = f[h + spc*seg_hdr_len + 32 : h + spc*seg_hdr_len + 32 + spc*32]
tail_pad = nextchmac + seghmacs_pad
tail_act = nextchmac + seghmacs_act
datas = {"hdrs_act": seghdrs_act, "hdrs_pad": seghdrs_pad,
         "hdrs_act+nextch": seghdrs_act+nextchmac, "hdrs_pad+nextch": seghdrs_pad+nextchmac,
         "empty": b""}
salts = {"tail_pad": tail_pad, "tail_act": tail_act, "seghmacs_pad": seghmacs_pad,
         "seghmacs_act": seghmacs_act, "nextch_only": nextchmac, "empty": b"",
         "rootmac": f[rootmac_off:rootmac_off+32], "auth": f[auth_start:auth_end],
         "hdrs_act": seghdrs_act, "hdrs_pad": seghdrs_pad,
         "chmac_next_stored": stored_chmac(k) if k+1 < len(clusters) else b"NONE"}
hit = []
for dn, dta in datas.items():
    for sn, slt in salts.items():
        if mac(chek, dta, slt) == stored:
            hit.append((dn, sn))
print("cluster2 chmac hits:", hit)
# sanity: also probe cluster 0 to confirm which combo matches there
h0, n0 = clusters[0]
ck0 = hkdf(main, b"", b"AEA_CK" + struct.pack("<I", 0))
chek0 = hkdf(ck0, b"", b"AEA_CHEK")
nextch0 = f[h0 + spc*seg_hdr_len : h0 + spc*seg_hdr_len + 32]
seghdrs_act0 = f[h0 : h0 + n0*seg_hdr_len]
seghdrs_pad0 = f[h0 : h0 + spc*seg_hdr_len]
seghmacs0 = f[h0 + spc*seg_hdr_len + 32 : h0 + spc*seg_hdr_len + 32 + spc*32]
tail0 = nextch0 + seghmacs0
hits0 = []
for dn, dta in [("hdrs_act", seghdrs_act0), ("hdrs_pad", seghdrs_pad0)]:
    for sn, slt in [("tail", tail0), ("nextch", nextch0), ("empty", b""), ("seghmacs", seghmacs0)]:
        if mac(chek0, dta, slt) == chmac0:
            hits0.append((dn, sn))
print("cluster0 chmac hits:", hits0)

# ---- content signature ----
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers, SECP256R1
x = int.from_bytes(point[1:33], "big"); y = int.from_bytes(point[33:65], "big")
vk = EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key()
sigfield = f[sig_off:sig_off+128]
# DER length
b1 = sigfield[1]
dl = 2+b1 if b1 < 0x80 else 3+sigfield[2]
dersig = sigfield[:dl]
r, s = decode_dss_signature(dersig)
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
newsig = encode_dss_signature(r, s)

end = chmac_off + 32
def prefix(zero_sig, start=0, upto=end):
    v = bytearray(f[start:upto])
    if zero_sig:
        for b in range(sig_off-start, sig_off-start+128): v[b] = 0
    return bytes(v)

datacands = {
    "pfx_sigzero": prefix(True),
    "pfx_raw": prefix(False),
    "pfx_sigzero_notillchmac": prefix(True, upto=rootmac_off+32),
    "pfx_to_rootmac": prefix(True, upto=rootmac_off),
    "pfx_auth0": prefix(True, start=auth_start),
    "roothdr48": f[root_off:root_off+0x30],
    "pfx_sigzero_nochmac": prefix(True, upto=chmac_off),
}
hashes = {"sha1": hashlib.sha1, "sha256": hashlib.sha256, "sha384": hashlib.sha384, "sha512": hashlib.sha512}
from cryptography.hazmat.primitives.asymmetric import utils as putils
hits = []
for dn, dta in datacands.items():
    # raw mode: library hashes the data itself (only SHA256 fits P-256 rules)
    for hn, hf in hashes.items():
        try:
            vk.verify(dersig, dta, ec.ECDSA(hf()))
            hits.append((dn, hn, "raw"))
        except Exception:
            pass
        # prehashed mode
        try:
            chash = {hashlib.sha256: ec.ECDSA(hf.__class__ and putils.Prehashed(ec.SECP256R1())),
                     }[hf] if False else putils.Prehashed(ec.SECP256R1())
            vk.verify(dersig, hf(dta).digest(), chash)
            hits.append((dn, hn, "prehash"))
        except Exception:
            pass
print("content sig hits:", hits)
