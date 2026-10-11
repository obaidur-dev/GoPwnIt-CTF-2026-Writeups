import json,hashlib,sys
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
D=sys.argv[1]
d=int(open(D+'/../d.txt').read(),16)
j=json.load(open(D+'/../bundle.json'))
N=int(j['modulus_N'],16);e1=int(j['e1']);e2=int(j['e2']);c1=int(j['c1'],16);c2=int(j['c2'],16)
def eg(a,b):
    if b==0:return a,1,0
    g,x,y=eg(b,a%b);return g,y,x-(a//b)*y
g,a,b=eg(e1,e2);print('gcd',g,a,b)
m=(pow(c1,a,N) if a>=0 else pow(pow(c1,-1,N),-a,N))*(pow(c2,b,N) if b>=0 else pow(pow(c2,-1,N),-b,N))%N
assert pow(m,e1,N)==c1 and pow(m,e2,N)==c2
T=m.to_bytes(32,'big');print('T',T.hex(), T)
pub=json.load(open(D+'/public.json'))
P=hashlib.sha256(b'ARGON/FINAL/v1'+d.to_bytes(32,'big')+T).digest()
ap=pub['vault']['argon2_params']
K=hash_secret_raw(P,bytes.fromhex(ap['final_salt']),time_cost=3,memory_cost=65536,parallelism=4,hash_len=32,type=Type.ID,version=19)
b=open(D+'/vault.enc','rb').read()
pt=AESGCM(K).decrypt(b[:12],b[28:]+b[12:28],b'ARGON/VAULT/v1')
print(pt)
