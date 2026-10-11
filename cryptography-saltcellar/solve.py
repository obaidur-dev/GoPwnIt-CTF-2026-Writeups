import re,sys,hashlib
from fpylll import IntegerMatrix, LLL, BKZ
D=sys.argv[1]; T=int(sys.argv[2])
N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
P=2**256-2**32-977; G=(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
STEP=0x9E3779B97F4A7C15
def add(a,b):
    if a is None:return b
    if b is None:return a
    if a[0]==b[0]:
        if (a[1]+b[1])%P==0:return None
        l=3*a[0]*a[0]*pow(2*a[1],-1,P)%P
    else:l=(b[1]-a[1])*pow(b[0]-a[0],-1,P)%P
    x=(l*l-a[0]-b[0])%P;return (x,(l*(a[0]-x)-a[1])%P)
def mul(k,pt=G):
    r=None
    while k:
        if k&1:r=add(r,pt)
        pt=add(pt,pt);k>>=1
    return r
t=open(D+'/signatures.txt').read()
Q=(int(re.search(r'public_key_x = (0x\w+)',t).group(1),16),int(re.search(r'public_key_y = (0x\w+)',t).group(1),16))
sigs=re.findall(r'message = "(.*?)"\s*r = (0x\w+)\s*s = (0x\w+)',t)
print(len(sigs),"sigs")
rows=[]
for m,r,s in sigs[:T]:
    h=int.from_bytes(hashlib.sha256(m.encode()).digest(),'big')%N
    r=int(r,16);s=int(s,16);inv=pow(STEP*s,-1,N)
    rows.append((inv*r%N, inv*h%N))   # m = A + B d, A=inv*h, B=inv*r
K=2**191; S=2**65; W=2**256
n=T+2
M=IntegerMatrix(n,n)
for i,(B,A) in enumerate(rows):
    M[i,i]=S*N
    M[T,i]=S*B
    M[T+1,i]=S*((A-K)%N)
M[T,T]=1; M[T+1,T+1]=W
LLL.reduction(M)
BKZ.reduction(M,BKZ.Param(block_size=20))
fl=bytes.fromhex(open(D+'/flag.enc').read().strip())
for i in range(n):
    v=[M[i,j] for j in range(n)]
    if abs(v[T+1])==W:
        for sg in (1,-1):
            d=(sg*v[T])%N
            if d and mul(d)==Q:
                print("d =",hex(d))
                ks=hashlib.sha256(d.to_bytes(32,'big')).digest()
                print(bytes(c^ks[j%32] for j,c in enumerate(fl)))
                sys.exit()
print("not found; shortest norms:",[round(M[i].norm()/2**256,2) for i in range(3)])
