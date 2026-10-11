# usage: python3 -I solve.py ping.pcap
import sys, hashlib, collections
import scapy.all as s
from Crypto.Cipher import AES
p = s.rdpcap(sys.argv[1])
reqs = [x for x in p if x.haslayer(s.ICMP) and x[s.ICMP].type == 8]
print("echo requests:", collections.Counter((x[s.IP].src, x[s.IP].dst, x[s.ICMP].id) for x in reqs))
q = [x for x in reqs if x[s.IP].src == "10.20.0.57"]

def tobytes(bits):
    bits = ''.join(map(str, bits)); n = len(bits)//8*8
    return bytes(int(bits[i:i+8], 2) for i in range(0, n, 8))

# channel 1: timing gaps (long ~1.25s = 1, short ~1.0s = 0)
t = [float(x.time) for x in q]
gaps = [t[i+1]-t[i] for i in range(len(t)-1)]
print("timing:", tobytes([1 if g > 1.12 else 0 for g in gaps]).rstrip(b'\0'))
# channel 2: TTL (65 = 1, 64 = 0)
print("ttl   :", tobytes([1 if x[s.IP].ttl == 65 else 0 for x in q]).rstrip(b'\0'))
# channel 3: low byte of IP-ID
b = bytes(x[s.IP].id & 255 for x in q)
L = int.from_bytes(b[:2], 'big'); nonce = b[2:14]; ct = b[14:14+L]
print("ip-id length field:", L)
key = hashlib.sha256(b'TIDEMARK-0619').digest()
for pl in range(1, L-15):          # find where ciphertext ends and 16-byte tag starts
    try:
        pt = AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct[:pl], ct[pl:pl+16])
        print("ip-id AES-GCM decrypted (tag OK):", pt.decode()); break
    except ValueError:
        pass
