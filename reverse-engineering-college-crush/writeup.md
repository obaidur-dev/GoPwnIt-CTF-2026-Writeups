# college_crush
**Category:** Reverse Engineering | **Difficulty:** Medium | **Points:** 100 | **Solves:** 107

## What the challenge was
A Windows program that asks `Enter The Flag :` and prints `Correct` or `Incorrect`. We had to find the input it accepts.

## How I solved it
1. The file ended in `.tgz` but `tar xzf` said "not in gzip format". `file` showed it's a 7-zip archive. I extracted it with `py7zr` and got one file, `college_crush.exe` (PE32+ x64). See [evidence/recon_output.txt](evidence/recon_output.txt).
2. `strings` showed `[value]`, `[key]`, `[target]`, `Correct`, `Incorrect`. It also showed a path with `Zware`. The exe has an odd section called `.zplus` (only 0x23 bytes).
3. I used `objdump -d -M intel` on the exe. `main` builds a table: `xor=0x7a`, `shl=0x70`, `shr=0x6c`, `comp=0x75`, `ret=0x73`, `[value]=0x11`, `[key]=0x22`, `[target]=0x33`. So `.zplus` is a tiny program for a VM inside the exe.
4. In the VM function I read what each op does (see [evidence/disasm_output.txt](evidence/disasm_output.txt)): `xor` = every byte ^ 0x5a, `shl` = `ror al,6`, `shr` = `ror al,2`, `comp` = compare the input with a 21-byte target. The target is stored as 5 dwords + 1 byte in `main`: `80a8d8bca4844c1434ec001438d4d41458ec808c9c`.
5. Dead end: I counted the `.zplus` bytes by hand and got 9 steps. I inverted that and got non-printable bytes (`\xdf\xd5\xc9...`). So my program was wrong.
6. To stop guessing I ran the real code in Unicorn (`verify_emu.py`). The parser printed the real program: `xor shl xor shl xor shr xor shl xor shr comp ret`. I had missed one `xor`. (`solve.py` also gets this when it groups the `.zplus` bytes the same way the exe does.)
7. I ran the steps backwards on the target (undo each step in reverse order). `python3 solve.py college_crush.exe` printed `zplus{I_WaZ_Too_Lazy}`.
8. I checked it in the emulator with the real VM function: `zplus{I_WaZ_Too_Lazy}` gives `Correct`. Changing the prefix or adding one character gives `Incorrect`. See [evidence/emulator_output.txt](evidence/emulator_output.txt).

## Flag
`GPI{I_WaZ_Too_Lazy}`

Note: the exe itself only accepts `zplus{I_WaZ_Too_Lazy}`, because the target it compares against is 21 bytes and the prefix is part of the comparison. In my emulator run `GPI{I_WaZ_Too_Lazy}` returned `Incorrect`, and changing the prefix or adding one character did too. The scoreboard takes the same body in the standard `GPI{...}` wrapper, and that is what I submitted.

## Tools used
- file, strings, objdump
- Python 3 with pefile, py7zr
- Unicorn (CPU emulator) to run the exe's real code
