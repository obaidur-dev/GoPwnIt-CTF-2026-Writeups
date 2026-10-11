# SHORTCUTS
**Category:** Reverse Engineering | **Difficulty:** Medium | **Points:** 100 | **Solves:** 96

## What the challenge was
I got `treasurebox.tgz`. The description asks what the treasurebox does and why it doesn't like my keys. So I had to find a key the box accepts.

## How I solved it
1. I ran `tar -tzvf treasurebox.tgz` and it failed with "not in gzip format". `file` showed it's really a RAR5 archive ([evidence/01_file_type.txt](evidence/01_file_type.txt)).
2. There was no `unrar` on my machine, so I wrote `extract.py` with libarchive. It gave one file, a stripped 64-bit ELF called `treasurebox` ([evidence/02_extract.txt](evidence/02_extract.txt)).
3. `strings` showed "The box happily accepts your key!" and "too short or too long". It also had a note from the author saying the section names were overwritten ([evidence/03_strings.txt](evidence/03_strings.txt)).
4. I ran `echo AAAA | ./treasurebox` and got "too short or too long". `strace` showed it reads up to 65 bytes, so the key is 64 characters plus a newline ([evidence/04_wrong_key_run.txt](evidence/04_wrong_key_run.txt), [evidence/05_strace_read.txt](evidence/05_strace_read.txt)).
5. I used `objdump -d -M intel` on the code at `0x1000`. The code puts the 64 chars in an 8x8 grid and swaps cells around. It swaps rows, columns and 2x2 block diagonals. It also swaps two neighbours when their sum is even. At the end it adds 2 to every cell ([evidence/06_disassembly.txt](evidence/06_disassembly.txt)).
6. It compares the grid with 8 strings stored at file offset `0x3020`: `algakrwu`, `mvauugrv`, `ppkcppwa`, `qkpatwif`, `qkknaema`, `vqpnuvak`, `ptapcgnw`, `gfgadfcc`.
7. I rewrote the steps in Python and checked them against the real binary on 300 random keys. All 300 matched ([evidence/08_solve_output.txt](evidence/08_solve_output.txt)).
8. Then I wrote the steps in reverse order in `solve.py`. I could not tell if two of the "if" passes run, so I tried all 4 combinations. Only one of them gave the target when I ran it forward, and the other 3 failed.
9. The good one is a readable 64 character sentence. I ran it in the real binary and it printed "The box happily accepts your key!" ([evidence/09_correct_key_run.txt](evidence/09_correct_key_run.txt)).

Run it: `python3 -I extract.py treasurebox.tgz out/` then `python3 -I solve.py out/treasurebox --selftest`

## Flag
`GPI{it_just_keeps_spinning_around_until_it_looks_nice_and_unreadable}`

The 64 character key the binary prints on success is the body of the flag. `treasurebox` never emits the `GPI{...}` wrapper itself, so the wrapper is added on submit. The key was confirmed against the real binary before submitting.

## Tools used
- file, tar
- Python 3 with libarchive-c
- strings, strace
- objdump, readelf
