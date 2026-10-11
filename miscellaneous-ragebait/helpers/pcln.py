import pefile, struct, sys
def load(path):
    pe = pefile.PE(path)
    base = pe.OPTIONAL_HEADER.ImageBase
    data = {}
    secs=[]
    for s in pe.sections:
        secs.append((s.Name.rstrip(b'\0').decode(), base+s.VirtualAddress, s.Misc_VirtualSize, s.get_data()))
    return pe, base, secs
def read(secs, va, n):
    for name, a, sz, d in secs:
        if a <= va < a+max(sz,len(d)):
            return d[va-a:va-a+n]
    return None
def find_pcln(secs):
    magics=[b'\xf1\xff\xff\xff\x00\x00',b'\xf0\xff\xff\xff\x00\x00',b'\xfa\xff\xff\xff\x00\x00']
    for name,a,sz,d in secs:
        for m in magics:
            i=d.find(m)
            while i!=-1:
                if d[i+6] in (1,2,4) and d[i+7]==8:
                    return a+i, d, i
                i=d.find(m,i+1)
def funcs(path):
    pe,base,secs=load(path)
    va,d,i=find_pcln(secs)
    # go1.20+: header: magic(4) pad(2) minLC(1) ptrsize(1) nfunc(8) nfiles(8) textStart(8) funcnameOff(8) cuOff pctabOff pclnOff
    nfunc,nfiles,textStart,fnOff,cuOff,ftab,pctab,pclnOff=struct.unpack_from('<8Q',d,i+8)
    tbl=i+pclnOff
    out=[]
    for k in range(nfunc):
        entryoff,funcoff=struct.unpack_from('<II',d,tbl+k*8)
        fo=i+pclnOff+funcoff
        e,nameoff=struct.unpack_from('<II',d,fo)
        nm=d[i+fnOff+nameoff:d.index(b'\0',i+fnOff+nameoff)].decode()
        out.append((textStart+entryoff,nm))
    return pe,base,secs,out
if __name__=='__main__':
    pe,base,secs,out=funcs(sys.argv[1])
    for a,n in out:
        if n.startswith('ragebait') or n.startswith('main'):
            print(hex(a),n)
