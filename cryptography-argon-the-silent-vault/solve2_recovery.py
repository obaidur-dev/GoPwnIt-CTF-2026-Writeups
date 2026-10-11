import json,hashlib,sys
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
D=sys.argv[1]
d=int(open(D+'/../d.txt').read(),16)
pub=json.load(open(D+'/public.json'))
salt=bytes.fromhex(pub['recovery_bundle']['wrap_salt'])
K=HKDF(hashes.SHA256(),32,salt,b'ARGON/RECOVERY/v1').derive(d.to_bytes(32,'big'))
b=open(D+'/recovery.enc','rb').read()
nonce,tag,ct=b[:12],b[12:28],b[28:]
pt=AESGCM(K).decrypt(nonce,ct+tag,b'ARGON/RECOVERY/v1')
print(pt[:300]); 
j=json.loads(pt)
print({k:(str(v)[:60]) for k,v in j.items()})
open(D+'/../bundle.json','wb').write(pt)
