#!/usr/bin/env python3
# Usage: python3 solve.py college_crush.exe      (needs: pip install pefile)
import struct, sys, pefile

pe = pefile.PE(sys.argv[1])
base = pe.OPTIONAL_HEADER.ImageBase
img = pe.get_memory_mapped_image()

# 1. opcode table. main() builds a map name -> number (seen in the disassembly)
names = {0x7a: 'xor', 0x70: 'shl', 0x6c: 'shr', 0x75: 'comp', 0x73: 'ret',
         0x11: '[value]', 0x22: '[key]', 0x33: '[target]'}

# 2. the program is the 0x23 bytes of the .zplus section
z = next(s for s in pe.sections if s.Name.startswith(b'.zplus'))
prog = img[z.VirtualAddress:z.VirtualAddress + 0x23]
print(".zplus bytes:", prog.hex(' '))

# 3. same grouping as the exe: first token 'ret' -> 2 tokens, any other -> 3 tokens
groups, cur, need = [], [], 0
for b in prog:
    t = names[b]
    if not cur:
        need = 2 if t == 'ret' else 3
    cur.append(t)
    if len(cur) == need:
        groups.append(cur); cur = []
if cur: groups.append(cur)
ops = [g[0] for g in groups]
print("program:", ' '.join(ops))

# 4. target bytes: main() stores them with mov DWORD PTR [rsp+0x30..0x40], imm32 and mov BYTE PTR [rsp+0x44], imm8
text = img[0x1000:0x1000 + 0x5d33]
target = b''
for off in (0x30, 0x34, 0x38, 0x3c, 0x40):
    i = text.find(b'\xc7\x44\x24' + bytes([off]))
    target += text[i + 4:i + 8]
i = text.find(b'\xc6\x44\x24\x44'); target += text[i + 4:i + 5]
print("target  :", target.hex(), len(target), "bytes")

# 5. ops from the disassembly: xor = ^0x5a, shl = ror 6 (rotate left 2), shr = ror 2
ror = lambda x, n: ((x >> n) | (x << (8 - n))) & 0xff
rol = lambda x, n: ror(x, 8 - n)
steps = [o for o in ops if o in ('xor', 'shl', 'shr')]
def fwd(b):
    for o in steps:
        b = bytes(c ^ 0x5a if o == 'xor' else ror(c, 6 if o == 'shl' else 2) for c in b)
    return b
def inv(b):
    for o in reversed(steps):
        b = bytes(c ^ 0x5a if o == 'xor' else rol(c, 6 if o == 'shl' else 2) for c in b)
    return b

answer = inv(target)
assert fwd(answer) == target
print("input that passes the check:", answer.decode())
