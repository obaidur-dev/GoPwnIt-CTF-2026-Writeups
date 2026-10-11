# Reads the decoy-flag list that main.main loops over (static slice in .data)
import struct, sys
sys.path.insert(0, '.')
from pcln import load, read
pe, base, secs = load(sys.argv[1])
a = 0x1400babe6 + 0x11493a   # rip-relative operand of the load after TrimSpace
b = 0x1400babed + 0x11493b
p = struct.unpack('<Q', read(secs, a, 8))[0]
n = struct.unpack('<Q', read(secs, b, 8))[0]
print('slice ptr', hex(p), 'count', n)
for i in range(n):
    sp, sl = struct.unpack('<QQ', read(secs, p + 16 * i, 16))
    print(i, sl, read(secs, sp, sl).decode())
