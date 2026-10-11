#!/usr/bin/env python3
# usage: python3 solve.py <folder with encore, choreography.dat, ...>
import sys, os, re, subprocess
D = os.path.abspath(sys.argv[1])
enc = open(f'{D}/encore','rb').read()
# tables inside the binary (.rodata, file offset = address)
S = enc[0x58e0:0x58e0+256]; perm = list(enc[0x58b8:0x58b8+10])
K = [enc[0x58a0+5*i:0x58a0+5*i+5] for i in range(4)]
rol = lambda x,n: ((x<<n)|(x>>(8-n))) & 255
ror = lambda x,n: ((x>>n)|(x<<(8-n))) & 255
def F(r,k):
    x=[rol(r[1],3)^((k[0]+r[0])&255), ror(r[2],3)^((k[1]+r[1])&255),
       rol(r[3],2)^((k[2]+r[2])&255), rol(r[4],4)^((k[3]+r[3])&255),
       ((r[4]+k[4])&255)^rol(r[0],1)]
    return [S[v] for v in x]
def T(f):                      # what the binary does to fragment 0
    s=[S[b] for b in f]; t=[0]*10
    for i in range(10): t[perm[i]]=s[i]
    L,R=t[:5],t[5:]
    for rd in range(4):
        y=F(R,K[rd]); L,R=R,[a^b for a,b in zip(L,y)]
    return bytes(L+R)
def Tinv(o):                   # undo it
    L,R=list(o[:5]),list(o[5:])
    for rd in (3,2,1,0):
        Rold=L; y=F(Rold,K[rd]); Lold=[a^b for a,b in zip(R,y)]; L,R=Lold,Rold
    t=L+R; s=[t[perm[i]] for i in range(10)]
    inv={S[i]:i for i in range(256)}
    return bytes(inv[b] for b in s)
c = open(f'{D}/choreography.dat','rb').read()
exp = c[0x90:0x9a]             # expected 10 bytes stored in choreography.dat
f0 = Tinv(exp); assert T(f0)==exp
print('expected from choreography.dat:', exp.hex()); print('fragment 0:', f0.hex())
frags=[f0.hex()]
def run_gdb(flag):
    gdbcmds=f'''set pagination off
set confirm off
break memcmp
commands
silent
printf "CMP n=%d\\n", $rdx
x/10xb $rdi
continue
end
run verify {flag}
quit
'''
    open('/tmp/_c.gdb','w').write(gdbcmds)
    return subprocess.run(['gdb','-q','-batch','-x','/tmp/_c.gdb','./encore'],cwd=D,capture_output=True,text=True).stdout
for k in range(1,5):
    flag='ENCORE{'+''.join(frags)+'0'*(20*(5-k))+'}'
    out=run_gdb(flag)
    # keep only the n=10 memcmp calls (the others are the dynamic loader)
    blocks=re.findall(r'CMP n=(\d+)\n((?:0x[0-9a-f]+[^\n]*\n){1,2})',out)
    ten=[re.findall(r'\t0x([0-9a-f]{2})',b[1]) for b in blocks if b[0]=='10']
    last=''.join(ten[-1]); frags.append(last)
    print(f'fragment {k}:', last, f'(from memcmp call #{len(ten)})')
flag='ENCORE{'+''.join(frags)+'}'
print('flag:', flag)
r=subprocess.run(['./encore','verify',flag],cwd=D,capture_output=True,text=True)
print(r.stdout); print('exit code', r.returncode)
