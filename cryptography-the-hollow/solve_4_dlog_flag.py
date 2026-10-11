import re,sys,hashlib
from math import isqrt, prod
from sympy.ntheory.modular import crt
D,S2,HB,FE=sys.argv[1:5]
t=open(S2).read()
p=int(re.search(r'p = (0x\w+)',t).group(1),16);g=2
y=int(re.search(r'y = (0x\w+)',t).group(1),16)
fs=[2,2039,4049,9203,10847,12413,21521,28813,37549,39821,43577,44687,48989,50651,50929,54091,57251,136973113,754799435023]
n=p-1
def bsgs(a,b,q):
    m=isqrt(q)+1
    tbl={};c=1
    for j in range(m): tbl.setdefault(c,j);c=c*a%p
    f=pow(a,-m,p);c=b
    for i in range(m+1):
        if c in tbl: return (i*m+tbl[c])%q
        c=c*f%p
    raise Exception("nolog")
res=[]
for q in fs:
    a=pow(g,n//q,p);b=pow(y,n//q,p)
    r=bsgs(a,b,q);res.append(r)
    assert pow(a,r,p)==b
M=prod(fs)
x,_=crt(fs,res); x=int(x)
print("M bits",M.bit_length(),"x bits",x.bit_length(), "g^x==y:",pow(g,x,p)==y)
Hb=open(HB,'rb').read()
xb=x.to_bytes((x.bit_length()+7)//8,'big')
fl=bytes.fromhex(open(FE).read().strip())
def ks(seed,n):
    o=b'';c=0
    while len(o)<n:
        o+=hashlib.sha256(seed+c.to_bytes(4,'big')).digest();c+=1
    return o[:n]
print(bytes(a^b for a,b in zip(fl,ks(hashlib.sha256(Hb+xb).digest(),len(fl)))))
