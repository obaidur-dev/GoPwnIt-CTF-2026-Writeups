#!/usr/bin/env python3
# Usage: python3 solve.py path/to/intercept.txt
import base64, collections, hashlib, re, string, sys

lines = [l for l in open(sys.argv[1]).read().splitlines() if l and not l.startswith('#')]
ct = base64.b64decode(''.join(lines))
print("ciphertext length:", len(ct))

# 1. find the key length with index of coincidence
def ic(s):
    c = collections.Counter(s); n = len(s)
    return sum(v * (v - 1) for v in c.values()) / (n * (n - 1))
for k in range(1, 20):
    v = sum(ic(ct[i::k]) for i in range(k)) / k
    print(f"key length {k:2d}  IC {v:.4f}")

# 2. crack each column of the repeating xor key by scoring English text
common = " etaoinshrdlu"
def score(bs):
    s = 0
    for x in bs:
        ch = chr(x)
        if ch in common: s += 3
        elif ch.lower() in string.ascii_lowercase: s += 2
        elif ch in string.printable and ch not in '\x0b\x0c': s += 0.5
        else: s -= 10
    return s
KL = 9
key = [max(range(256), key=lambda k: score([c ^ k for c in ct[i::KL]])) for i in range(KL)]
print("xor key:", key)
memo = bytes(c ^ key[i % KL] for i, c in enumerate(ct)).decode()
print("-----MEMO-----"); print(memo); print("--------------")

# 3. follow the memo: operator code -> dispatch key
code = re.search(r"operator code for this week is GPI\{(.*?)\}", memo).group(1)
letters = [c for c in code if c.isalpha()]
dkey = ''.join(chr((ord(c.lower()) - 97 + i + 1) % 26 + 97) for i, c in enumerate(letters))
print("operator code:", code); print("dispatch key :", dkey)

# 4. open the sealed line: xor with repeated sha256(key)
sealed = re.search(r"sealed line \(base64\):\s*(\S+)", memo).group(1)
d = hashlib.sha256(dkey.encode()).digest()
plain = bytes(c ^ d[i % 32] for i, c in enumerate(base64.b64decode(sealed))).decode()
print("sealed line  :", plain)
print("flag         :", plain.split(": ", 1)[1])
