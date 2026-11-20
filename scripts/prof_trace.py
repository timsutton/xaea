import sys, collections
import xml.etree.ElementTree as ET
tree=ET.parse(sys.argv[1]); root=tree.getroot()
frames={}  # id -> name
bts={}     # id -> list of names
def fname(f):
    if 'id' in f.attrib: frames[f.attrib['id']]=f.attrib.get('name','?')
    return frames.get(f.attrib.get('id') or f.attrib.get('ref'),'?')
cls_leaf=collections.defaultdict(collections.Counter)
cls_incl=collections.defaultdict(collections.Counter)
cls_tot=collections.Counter()
idle=collections.Counter()
for row in root.iter('row'):
    bt=row.find('tagged-backtrace')
    if bt is None: continue
    if 'ref' in bt.attrib and not list(bt): names=bts[bt.attrib['ref']]
    else:
        names=[fname(f) for f in bt.iter('frame')]
        if 'id' in bt.attrib: bts[bt.attrib['id']]=names
    st=row.find('thread-state'); st=(st.attrib.get('fmt') if st is not None and 'fmt' in st.attrib else '')
    j=' '.join(names)
    if 'writer_loop' in j: c='writer'
    elif 'decode_segment' in j or 'lzma' in j.lower(): c='decoder'
    elif 'verify_segment_macs' in j or 'Sha256' in j and 'decode' not in j: c='segmac'
    elif 'extract_body' in j or 'main' in names[-3:] : c='main/parser'
    else: c='other'
    cls_tot[c]+=1
    if names: cls_leaf[c][names[0][:110]]+=1
    for n in set(names): cls_incl[c][n[:110]]+=1
print("samples (1ms each) per class:", dict(cls_tot))
for c in ['writer','decoder','main/parser','segmac','other']:
    if not cls_tot[c]: continue
    print(f"\n=== {c} ({cls_tot[c]} samples): top LEAF frames")
    for n,k in cls_leaf[c].most_common(14): print(f"  {k:6d} {100*k/cls_tot[c]:5.1f}%  {n}")
    print(f"--- {c}: top INCLUSIVE frames")
    for n,k in cls_incl[c].most_common(28): print(f"  {k:6d} {100*k/cls_tot[c]:5.1f}%  {n}")
