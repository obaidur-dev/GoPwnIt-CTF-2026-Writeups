#!/usr/bin/env python3
"""Ragebait solver.
1. Pull every GPI{...} string out of the binary.
2. Run the real exe (under wine) once per string.
3. The only one that prints "TRUE GOD TIER ACHIEVED" is the flag.
Usage: python3 solve.py dist/golev_windows_amd64.exe
"""
import re, subprocess, sys, os

exe = sys.argv[1] if len(sys.argv) > 1 else "dist/golev_windows_amd64.exe"
data = open(exe, "rb").read()
cands = sorted(set(m.decode() for m in re.findall(rb"GPI\{[ -~]{3,60}?\}", data)))
print(f"found {len(cands)} GPI{{}} strings in {exe}\n")

env = dict(os.environ, WINEDEBUG="-all", WINEPREFIX="/tmp/wp")
winner = None
for c in cands:
    out = subprocess.run(["wine64", exe], input=c + "\nexit\n", env=env,
                         capture_output=True, text=True, timeout=120).stdout
    if "TRUE GOD TIER ACHIEVED" in out:
        verdict = "SUCCESS banner"; winner = c
    elif "RECONSTRUCTION TRAP" in out:
        verdict = "AI reconstruction trap"
    elif "DECOY FLAG DETECTED" in out:
        verdict = "decoy"
    else:
        verdict = "other / taunt"
    print(f"{verdict:24s} {c}")

print("\nFLAG:", winner)
