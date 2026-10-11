import sys, struct
from capstone import *
from pcln import funcs, read
path=sys.argv[1]; names=sys.argv[2:]
pe,base,secs,fl=funcs(path)
fl.sort()
addr2n={a:n for a,n in fl}
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=False
def sym(a):
    if a in addr2n: return addr2n[a]
def strat(a):
    b=read(secs,a,80)
    if not b: return None
    s=b.split(b'\0')[0]
    try:
        t=s.decode('ascii')
        return t[:70]
    except: return None
for idx,(a,n) in enumerate(fl):
    if n not in names: continue
    end=fl[idx+1][0]
    code=read(secs,a,end-a)
    print(f"=== {n} @ {hex(a)} size {end-a}")
    for ins in md.disasm(code,a):
        extra=''
        if ins.mnemonic in('call','jmp') and ins.op_str.startswith('0x'):
            s=sym(int(ins.op_str,16)); 
            if s: extra=' ; '+s
        if 'rip' in ins.op_str and ins.mnemonic=='lea':
            import re
            m=re.search(r'rip ([+-]) (0x[0-9a-f]+)',ins.op_str)
            if m:
                t=ins.address+ins.size+(int(m.group(2),16)*(1 if m.group(1)=='+' else -1))
                s=strat(t)
                extra=f' ; ->{hex(t)} {s!r}'
        print(f"{ins.address:x}: {ins.mnemonic} {ins.op_str}{extra}")
