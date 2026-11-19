#!/usr/bin/env python3 -I
"""Walk AA01 object-stream records across N decompressed segments."""
import struct, lzma, sys, collections

class Walker:
    def __init__(self):
        self.cb = None
        self.carry = b""
        self.rem_blob = 0
        self.blob_total = 0

    def feed(self, d):
        if self.rem_blob:
            take = min(self.rem_blob, len(d))
            self.blob_total += take
            self.rem_blob -= take
            d = d[take:]
            if self.rem_blob:
                return
        buf = self.carry + d
        pos = 0
        while True:
            if len(buf) - pos < 6:
                self.carry = buf[pos:]
                return
            if buf[pos:pos+4] != b"AA01":
                raise SystemExit(f"bad magic at {pos}: {buf[pos:pos+40].hex()}")
            size = struct.unpack_from("<H", buf, pos+4)[0]
            if len(buf) - pos < size:
                self.carry = buf[pos:]
                return
            body = buf[pos+6:pos+size]
            q = 0
            fields = {}
            while q < len(body):
                tag = body[q:q+4]; fmt = tag[3]; key = tag[:3].decode()
                if fmt == ord('P'):
                    ln = struct.unpack_from("<H", body, q+4)[0]
                    fields[key] = body[q+6:q+6+ln]; q += 6+ln
                elif fmt == ord('p'):
                    ln = struct.unpack_from("<I", body, q+4)[0]
                    fields[key] = body[q+8:q+8+ln]; q += 8+ln
                elif fmt in (ord('1'), ord('2'), ord('4'), ord('8')):
                    w = fmt-48
                    fields[key] = int.from_bytes(body[q+4:q+4+w], "little"); q += 4+w
                elif fmt in (ord('A'), ord('B'), ord('C')):
                    w = 2 << (fmt - ord('A'))
                    fields[key] = int.from_bytes(body[q+4:q+4+w], "little"); q += 4+w
                else:
                    raise SystemExit(f"tag {tag!r} fmt {chr(fmt)} q={q} {body.hex()}")
            bloblen = fields.get('DAT', 0)
            avail = len(buf) - pos - size
            take = min(bloblen, avail)
            if self.cb:
                self.cb(size, fields, take)
            self.blob_total += take
            pos += size + take
            if bloblen > take:
                self.rem_blob = bloblen - take
                self.carry = b""
                return
            self.carry = b""

def main():
    nsegs = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    f = open("fixtures/Xcode_27.3_beta_2.aea", "rb")
    hdr = f.read(20000)
    auth = struct.unpack_from("<I", hdr, 8)[0]
    pk = 12+auth+128; ch = pk+96+0x30
    spc = 256
    sizes = [struct.unpack_from("<I", hdr, ch+32+i*40+4)[0] for i in range(spc)]
    data_off = ch+32+spc*40+32+spc*32
    tagsets = collections.Counter()
    shapes = collections.Counter()
    flags = collections.Counter()
    st = collections.Counter()
    odd = []
    def cb(size, fl, blobtake):
        st['nrec'] += 1
        tagsets[tuple(sorted(fl.keys()))] += 1
        shapes[chr(fl.get('TYP', 0))] += 1
        flags[(fl.get('FLG'), fl.get('AFT'))] += 1
        st['maxdat'] = max(st['maxdat'], fl.get('DAT', 0))
        if len(odd) < 12:
            extra = set(fl) - {'TYP','PAT','UID','GID','MOD','DAT','FLG','AFT','LNK'}
            if extra:
                odd.append((sorted(fl), {k: (fl[k] if not isinstance(fl[k], bytes) or len(fl[k]) < 60 else fl[k][:60]) for k in extra}))
    w = Walker(); w.cb = cb
    for i in range(nsegs):
        f.seek(data_off + sum(sizes[:i]))
        w.feed(lzma.decompress(f.read(sizes[i])))
    print("records:", st['nrec'], "blob bytes:", w.blob_total)
    print("types:", dict(shapes), "max DAT:", st['maxdat'])
    print("FLG/AFT:", dict(flags))
    for k, v in tagsets.items():
        print(" ", v, k)
    for o in odd:
        print("ODD:", o)

if __name__ == "__main__":
    main()
