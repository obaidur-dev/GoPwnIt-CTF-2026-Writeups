# Ragebait
**Category:** Miscellaneous | **Difficulty:** Hard | **Points:** 50 | **Solves:** 55

## What the challenge was
We got a zip with two Go programs (`golev_linux_amd64` and `golev_windows_amd64.exe`). The program asks for a flag and makes fun of you. The goal was to find the real flag out of many fake ones.

## How I solved it
1. I unzipped the file and ran `file dist/*`. Both files are Windows PE files, even the "linux" one. They are almost the same program. ![files](evidence/01_files.txt)
2. I ran `strings -n 6 dist/golev_linux_amd64 | grep -o 'GPI{[^}]*}'`. I got 18 different `GPI{...}` strings. The program itself says strings won't give the flag, so most must be fake. ![strings](evidence/02_strings.txt)
3. I wrote a small script (`helpers/pcln.py`) to read the Go function table. It shows the real code is in `main.main` and the `engine` and `crypto` packages (Feistel cipher, 7 goroutines, Levenshtein). ![functions](evidence/03_go_functions.txt)
4. I disassembled `main.main` (`helpers/gdis.py`). The input is checked in this order: a list of 15 decoys, then two special strings (length 0x28 and length 0x25), then a 32 byte cipher pipeline. ![dispatch](evidence/04_main_dispatch.txt)
5. I read the decoy list from the `.data` section with `helpers/decoylist.py`. It has 15 fake flags. The two special strings aren't in it. ![decoys](evidence/05_decoy_list.txt)
6. The 0x25 long string `GPI{g0_l3v_3g0_sh4tt3r3d_n0_41_9f82c}` prints a 1425 byte message: "AI DETECTED: THE RECONSTRUCTION TRAP". It says the real flag needs native execution. So this one is a trap for people who only reverse the cipher. ![trap](evidence/06_trap_banner_string.txt)
7. The 0x28 long string `GPI{b3y0nd_41_l0g1c_r3c0nstruct10n_9f82}` calls `GetBinaryRuntimeHash`. That function reads its own exe and does SHA-256. If it works, the code prints the "TRUE GOD TIER" banner. This is the only path to a success message.
8. I installed wine (`apt-get update && apt-get install wine64`) and ran the exe for real. The first `apt-get install` failed with 404 errors, so I had to run `apt-get update` first. 
9. I ran `python3 solve.py dist/golev_windows_amd64.exe`. It feeds all 18 strings to the exe. Only one printed the success banner. ![solve output](evidence/07_solve_output.txt)
10. I also ran the flag by hand and saw `OFFICIAL TOURNAMENT FLAG: GPI{b3y0nd_...}`. The trap string gave the AI trap banner instead. ![flag run](evidence/08_run_flag.txt) ![trap run](evidence/09_run_trap.txt)

## Flag
`GPI{b3y0nd_41_l0g1c_r3c0nstruct10n_9f82}`

## Tools used
- unzip, file, strings
- Python 3 with pefile and capstone (own scripts in `helpers/`)
- wine64 (to run the Windows exe)
