#!/usr/bin/env python3
# Usage: python3 verify_emu.py college_crush.exe     (needs: pip install pefile unicorn)
# Runs the REAL code of the exe inside Unicorn (no Windows needed):
#   1. static init (builds the opcode maps)
#   2. the program parser (140001480) -> prints the real program text
#   3. the VM function (140001e10) on a few inputs -> prints Correct / Incorrect
import sys, struct, pefile
from unicorn import *
from unicorn.x86_const import *

pe=pefile.PE(sys.argv[1])
BASE=0x140000000
img=pe.get_memory_mapped_image()
mu=Uc(UC_ARCH_X86,UC_MODE_64)
size=(len(img)+0xfff)&~0xfff
mu.mem_map(BASE,size)
mu.mem_write(BASE,img)
STACK=0x7ff00000; mu.mem_map(STACK-0x100000,0x200000)
HEAP=0x10000000; mu.mem_map(HEAP,0x1000000)
heap_ptr=[HEAP]
STUB=0x50000000; mu.mem_map(STUB,0x10000)
mu.mem_write(STUB,b'\xc3'*0x10000)
# TEB gs for stack cookie etc not needed
names={}
i=0
for e in pe.DIRECTORY_ENTRY_IMPORT:
    for imp in e.imports:
        addr=STUB+i*16; i+=1
        nm=imp.name.decode() if imp.name else str(imp.ordinal)
        names[addr]=nm
        mu.mem_write(imp.address-pe.OPTIONAL_HEADER.ImageBase+BASE if imp.address<BASE else imp.address, struct.pack('<Q',addr))

def alloc(n):
    p=(heap_ptr[0]+15)&~15
    heap_ptr[0]=p+n+16
    return p
log=[]
def hook_code(uc,address,sz,ud):
    if STUB<=address<STUB+0x10000:
        nm=names.get(address-((address-STUB)%16),None)
        rsp=uc.reg_read(UC_X86_REG_RSP)
        ret=struct.unpack('<Q',uc.mem_read(rsp,8))[0]
        rcx=uc.reg_read(UC_X86_REG_RCX);rdx=uc.reg_read(UC_X86_REG_RDX);r8=uc.reg_read(UC_X86_REG_R8)
        rax=0
        if nm=='malloc': rax=alloc(rcx)
        elif nm=='free': pass
        elif nm in('memcpy','memmove'):
            uc.mem_write(rcx,bytes(uc.mem_read(rdx,r8))); rax=rcx
        elif nm=='memset':
            uc.mem_write(rcx,bytes([rdx&255])*r8); rax=rcx
        elif nm=='memcmp':
            a=bytes(uc.mem_read(rcx,r8));b=bytes(uc.mem_read(rdx,r8))
            rax=0 if a==b else (1 if a>b else 0xffffffff)
        elif nm=='strlen':
            n=0
            while uc.mem_read(rcx+n,1)!=b'\x00': n+=1
            rax=n
        elif nm in ('_crt_atexit','_register_onexit_function'): rax=0
        else:
            log.append(nm)
        uc.reg_write(UC_X86_REG_RAX,rax)
        uc.reg_write(UC_X86_REG_RSP,rsp+8)
        uc.reg_write(UC_X86_REG_RIP,ret)
mu.hook_add(UC_HOOK_CODE,hook_code)
RET=0x50008000  # sentinel
def call(fn,args=(),maxins=10**7):
    rsp=STACK-0x1000
    rsp-=8
    mu.mem_write(rsp,struct.pack('<Q',RET))
    # shadow space
    regs=[UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9]
    for r,a in zip(regs,args): mu.reg_write(r,a)
    mu.reg_write(UC_X86_REG_RSP,rsp)
    mu.emu_start(fn,RET,count=maxins)
    return mu.reg_read(UC_X86_REG_RAX)
def rd(a,n): return bytes(mu.mem_read(a,n))
def wr(a,b): mu.mem_write(a,b)
def q(a): return struct.unpack('<Q',rd(a,8))[0]

call(0x140001000)
def mkstr(s):
    b=s.encode(); p=alloc(32)
    if len(b)<16: buf=(b+b'\x00'*16)[:16]
    else:
        a=alloc(len(b)+1); wr(a,b+b'\0'); buf=struct.pack('<Q',a)+b'\0'*8
    wr(p,buf+struct.pack('<QQ',len(b),max(15,len(b))))
    return p
def mkgroup(toks):
    ptrs=[mkstr(t) for t in toks]
    arr=alloc(32*len(toks))
    for i,p in enumerate(ptrs): wr(arr+32*i,rd(p,32))
    g=alloc(24); wr(g,struct.pack('<QQQ',arr,arr+32*len(toks),arr+32*len(toks))); return g
def mkprog(prog):
    gs=[mkgroup(t) for t in prog]
    arr=alloc(24*len(gs))
    for i,g in enumerate(gs): wr(arr+24*i,rd(g,24))
    pv=alloc(24); wr(pv,struct.pack('<QQQ',arr,arr+24*len(gs),arr+24*len(gs))); return pv
def mkvec(b):
    a=alloc(len(b)+1); wr(a,b); v=alloc(24); wr(v,struct.pack('<QQQ',a,a+len(b),a+len(b))); return v
def run(pv,inp,t):
    res=alloc(32); iv=mkvec(inp); tv=mkvec(t)
    call(0x140001e10,(res,pv,iv,tv))
    return rd(q(iv),len(inp)), rd(res,16).split(b'\0')[0]

# ---- 2. capture the program text the exe builds from .zplus ----
text=[]
def hook_stream(uc,address,sz,ud):
    rsp=uc.reg_read(UC_X86_REG_RSP)
    if address in (0x140003840,0x1400028e0):   # ostream write helpers inside the exe
        rcx=uc.reg_read(UC_X86_REG_RCX);rdx=uc.reg_read(UC_X86_REG_RDX);r8=uc.reg_read(UC_X86_REG_R8)
        if address==0x140003840: s=rd(rdx,r8)
        else:
            n=0
            while rd(rdx+n,1)!=b'\0': n+=1
            s=rd(rdx,n)
        text.append(s)
        ret=struct.unpack('<Q',rd(rsp,8))[0]
        uc.reg_write(UC_X86_REG_RAX,rcx); uc.reg_write(UC_X86_REG_RSP,rsp+8); uc.reg_write(UC_X86_REG_RIP,ret)
    elif address==0x140001800:                 # end of the parse loop
        uc.emu_stop()
h=mu.hook_add(UC_HOOK_CODE,hook_stream)
call(0x140001480,(alloc(64),))
mu.hook_del(h)
ptext=b''.join(text).decode()
print("program text built by the exe:"); print(ptext)
real_prog=[l.split() for l in ptext.strip().split('\n')]

target=bytes.fromhex("80a8d8bca4844c1434ec001438d4d41458ec808c9c")
# ---- 3. run the VM function ----
for inp in (b"zplus{I_WaZ_Too_Lazy}", b"GPI{I_WaZ_Too_Lazy}", b"zplus{I_WaZ_Too_Lazy!}"):
    out,res=run(mkprog(real_prog),inp,target)   # a fresh program each time, the VM frees it
    print(f"{inp.decode():28s} -> {res.decode()}")

# ---- my first wrong try: I hand-read .zplus and missed one xor ----
ror=lambda x,n:((x>>n)|(x<<(8-n)))&0xff
rol=lambda x,n:ror(x,8-n)
wrong=['x',6,'x',6,'x',2,'x',6,2]
b=target
for o in reversed(wrong): b=bytes(c^0x5a if o=='x' else rol(c,o) for c in b)
print("wrong 9-step program gives:",b)
