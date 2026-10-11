import sys, hashlib, re
D=sys.argv[1]
R=0xE1<<120
def mul(x,y):
    z=0; v=x
    for i in range(128):
        if (y>>(127-i))&1: z^=v
        v = (v>>1)^R if v&1 else v>>1
    return z
def pw(a,n):
    r=1<<127  # identity: x^0 coefficient = MSB
    while n:
        if n&1:r=mul(r,a)
        a=mul(a,a);n>>=1
    return r
def inv(a): return pw(a,(1<<128)-2)
def sqrt(a): return pw(a,1<<127)
txt=open(D+'/envelopes.txt').read()
envs=re.findall(r'nonce\s*=\s*(\w+)\s*ciphertext\s*=\s*(\w+)\s*tag\s*=\s*(\w+)',txt)
E=[(bytes.fromhex(n),bytes.fromhex(c),int(t,16)) for n,c,t in envs]
assert len(set(e[0] for e in E))==1
B=[int.from_bytes(e[1].ljust(16,b'\0'),'big') for e in E]
T=[e[2] for e in E]
print("cts len",[len(e[1]) for e in E])
cands=set()
for i,j in [(0,1),(0,2),(1,2)]:
    h2=mul(T[i]^T[j],inv(B[i]^B[j])); cands.add(sqrt(h2))
print([hex(c) for c in cands])
H=cands.pop(); assert not cands
Hb=H.to_bytes(16,'big')
nonce=E[0][0]
def ks(seed,n):
    o=b'';c=0
    while len(o)<n:
        o+=hashlib.sha256(seed+c.to_bytes(4,'big')).digest();c+=1
    return o[:n]
for n,c,t in E:
    k=ks(Hb+n,len(c)); print("pt",bytes(a^b for a,b in zip(c,k)))
    L=len(c)*8; acc=mul(int.from_bytes(c.ljust(16,b'\0'),'big'),H)
    acc=mul(acc^L,H); S=int.from_bytes(hashlib.sha256(Hb+n+b'tag').digest()[:16],'big')
    print("tag ok",(acc^S)==t)
# stage2
s2=open(D+'/stage2.bin','rb').read()
seed=hashlib.sha256(Hb).digest()
pt=bytes(a^b for a,b in zip(s2,ks(seed,len(s2))))
print(pt.decode(errors='replace'))
open(sys.argv[2],'wb').write(Hb); open(sys.argv[3],'wb').write(pt)
