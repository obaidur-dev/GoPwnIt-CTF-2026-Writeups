import json, sys, hashlib, struct
from fpylll import IntegerMatrix, LLL, BKZ
D=sys.argv[1]
n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G=(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
sigs=[json.loads(l) for l in open(D+'/signatures.jsonl') if l.strip()]
raw=open(D+'/diagnostics.bin','rb').read()
diag={}
for o in range(0,len(raw),20):
    u,c,h=struct.unpack('>16sHH',raw[o:o+20]); diag[u.hex()]=(c,h)
print(len(sigs),len(diag),set(c for c,h in diag.values()), sum(s['id'] in diag for s in sigs))
T=[];A=[]
for s in sigs:
    r=int(s['r'],16); ss=int(s['s'],16)
    z=int.from_bytes(hashlib.sha256(s['message'].encode()).digest(),'big')%n
    h=diag[s['id']][1]
    w=pow(ss,-1,n)
    T.append(r*w%n); A.append((z*w - h*2**244 - 2**243)%n)
m=len(T); B=2**243
M=IntegerMatrix(m+2,m+2)
for i in range(m): M[i,i]=n*n
for i in range(m): M[m,i]=n*T[i]
M[m,m]=B
for i in range(m): M[m+1,i]=n*A[i]
M[m+1,m+1]=B*n
# lattice is (m+2)x(m+2): columns 0..m-1 are the modulus rows, column m is d,
# column m+1 is the constant (2^256 for the d row, B*n for the a row)
LLL.reduction(M)
BKZ.reduction(M,BKZ.Param(block_size=20))
Q=(0xc8fd5e28f3ac7865021962ba4707ad5a053031e59759832bcc652547b0e61911,0xdf30a3ba752fee6db8afc77591f67b791476f4111c785828dd102756c8208eda)
def add(P,R):
    if P is None:return R
    if R is None:return P
    if P[0]==R[0]:
        if (P[1]+R[1])%p==0:return None
        l=3*P[0]*P[0]*pow(2*P[1],-1,p)%p
    else:l=(R[1]-P[1])*pow(R[0]-P[0],-1,p)%p
    x=(l*l-P[0]-R[0])%p;return (x,(l*(P[0]-x)-P[1])%p)
p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
def mul(k,P):
    R=None
    while k:
        if k&1:R=add(R,P)
        P=add(P,P);k>>=1
    return R
found=None
for row in range(m+2):
    v=[M[row,j] for j in range(m+2)]
    if abs(v[m+1])==B*n:
        sgn=1 if v[m+1]>0 else -1
        for cand in (sgn*v[m]//B, -sgn*v[m]//B):
            for d in (cand%n,(-cand)%n):
                if d and mul(d,G)==Q: found=d
    if found: break
print('d =',hex(found) if found else None)
open(D+'/../d.txt','w').write(hex(found) if found else '')
