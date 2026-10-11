# usage: python3 -I solve.py <folder with logs.txt traffic.pcap memory.mem>
import re, struct, base64, sys
D = sys.argv[1]

# part 1: milliseconds of the SSH failure lines in logs.txt
ms = []
for line in open(D + "/logs.txt"):
    if "SSH Login failure" in line:
        ms.append(int(re.search(r":\d\d\.(\d{3})\]", line).group(1)))
print("ssh ms values:", ms)
p1 = "".join(chr(x) for x in ms)
print("part1:", p1)

# part 2: session_id cookies in traffic.pcap (capture order) + auth_token
pc = open(D + "/traffic.pcap", "rb").read()
o = 24; ids = []; tok = None
while o < len(pc):
    cl = struct.unpack("<I", pc[o+8:o+12])[0]; o += 16
    pkt = pc[o:o+cl]; o += cl
    m = re.search(rb"session_id=([^;]+); auth_token=(\d+)", pkt)
    if m:
        ids.append(m.group(1).decode()); tok = int(m.group(2))
print("session ids:", ids, "auth_token:", tok)
p2 = "".join(base64.b64decode(i).decode() for i in ids)
print("part2:", p2)

# part 3: payload at 0x600000 (ends at [PAYLOAD_END]) xor auth_token
mem = open(D + "/memory.mem", "rb").read()
end = mem.find(b"[PAYLOAD_END]")
print("payload end marker at:", hex(end))
pay = mem[0x600000:end]
dec = bytes(b ^ tok for b in pay)
print("payload xor", tok, "->", dec)
p3 = re.search(rb"[ -~]{6,}$", dec).group().decode()   # readable tail
print("part3:", p3)

print("FLAG:", p1 + p2 + p3)
