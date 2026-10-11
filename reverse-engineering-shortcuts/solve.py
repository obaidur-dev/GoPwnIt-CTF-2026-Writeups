#!/usr/bin/env python3
# SHORTCUTS (treasurebox) solver.
# usage: python3 -I solve.py <path to treasurebox> [--selftest]
#
# What the binary does (from the disassembly):
#   1. reads 64 chars, puts them in an 8x8 grid (row by row)
#   2. swaps neighbours in rows, then columns, then 2x2 block diagonals
#   3. swaps neighbours in a row when (a+b) is even  (checked on signed bytes)
#   4. block diagonal swap again
#   5. two extra "if" passes that depend on a few cells
#   6. adds 2 to every cell
#   7. compares with 8 strings stored at file offset 0x3020 (stride 9)
# I undo the steps in reverse order. The two "if" passes are unknown
# (they may or may not run), so I try all 4 combos and keep the one
# that gives the target when I run it forward.
import itertools
import random
import re
import subprocess
import sys


def s8(x):
    return x - 256 if x >= 128 else x


def rowswap(G):
    for i in (0, 2, 4, 6):
        G[i], G[i + 1] = G[i + 1], G[i]


def colswap(G):
    for r in range(8):
        for c in (0, 2, 4, 6):
            G[r][c], G[r][c + 1] = G[r][c + 1], G[r][c]


def blk(G):
    for r in (0, 2, 4, 6):
        for c in (0, 2, 4, 6):
            G[r][c], G[r + 1][c + 1] = G[r + 1][c + 1], G[r][c]


def cond(G, want_even, reverse=False):
    for r in range(8):
        cols = range(6, -1, -1) if reverse else range(7)
        for c in cols:
            s = (s8(G[r][c]) + s8(G[r][c + 1])) & 0xFFFF
            if ((s & 1) == 0) == want_even:
                G[r][c], G[r][c + 1] = G[r][c + 1], G[r][c]


def forward(key):
    G = [list(key[i * 8:i * 8 + 8]) for i in range(8)]
    rowswap(G)
    colswap(G)
    blk(G)
    cond(G, True)
    blk(G)
    if G[1][0] % 2 == 0 or G[1][7] % 2 == 0:
        cond(G, True)
    if G[0][1] % 2 == 1 or G[2][7] % 2 == 1:
        cond(G, False)
    for r in G:
        for c in range(8):
            r[c] = (r[c] + 2) & 0xFF
    return bytes(b for r in G for b in r)


def run_binary(path, key):
    p = subprocess.run([path], input=key + b"\n", capture_output=True, timeout=5)
    return p.stdout


def main():
    path = sys.argv[1]
    data = open(path, "rb").read()
    targets = [data[0x3020 + 9 * i:0x3020 + 9 * i + 8] for i in range(8)]
    target = b"".join(targets)
    print("targets at 0x3020:", targets)

    if "--selftest" in sys.argv:
        ok = 0
        for _ in range(300):
            key = bytes(random.choice(range(0x21, 0x7F)) for _ in range(64))
            out = run_binary(path, key)
            m = re.search(rb"\+---> (.{64}) ---\+", out, re.S)
            if m and m.group(1) == forward(key):
                ok += 1
        print("selftest: my forward() matches the real binary on", ok, "of 300 random keys")

    base = [[(b - 2) & 0xFF for b in row] for row in targets]
    found = []
    for u7, u6 in itertools.product((0, 1), (0, 1)):
        G = [r[:] for r in base]
        if u7:
            cond(G, False, reverse=True)
        if u6:
            cond(G, True, reverse=True)
        blk(G)
        cond(G, True, reverse=True)
        blk(G)
        colswap(G)
        rowswap(G)
        key = bytes(b for r in G for b in r)
        good = forward(key) == target
        print(u7, u6, key, "forward == target:", good)
        if good:
            found.append(key)

    print(len(found), "valid key(s)")
    for key in found:
        out = run_binary(path, key)
        print("binary says accepted:", b"happily accepts" in out)
        print("KEY:", key.decode())
        print("FLAG: GPI{" + key.decode() + "}")


main()
