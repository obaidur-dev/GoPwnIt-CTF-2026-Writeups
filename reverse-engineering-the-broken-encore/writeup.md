# SHAKIRA The Broken Encore
**Category:** Reverse Engineering | **Difficulty:** Hard | **Points:** 150 | **Solves:** 43

## What the challenge was
A Linux program `encore` checks a flag of the form `ENCORE{...}` (108 characters). The flag is 5 pieces of 10 bytes each, written in hex. Each piece is checked by a different stage (footwork, rhythm VM, vault, lights, encore).

## How I solved it
1. I unzipped the package and ran `./encore verify ENCORE{0123...}`. It said the flag length must be 108, so the flag is `ENCORE{` + 100 hex chars + `}` = 5 pieces of 20 hex chars.
2. I read the disassembly with `objdump -d -M intel encore`. Main splits the flag into 5 pieces and calls one check per piece. Each check compares its result with the next piece using `memcmp`.
3. Stage 1 (footwork): the program loads `choreography.dat`, runs piece 0 through an S-box, a byte permutation and 4 Feistel rounds, and compares with 10 bytes stored in the file (`7bc8386f3a8f30eaaf8a`). I copied the tables from the binary and wrote the reverse of this in Python (`solve.py`). That gave piece 0 = `2372f289d37d29394982`.
4. With piece 0 set, the program passed stage 1 and its own rhythm VM (`rhythm.bc`) computed the expected piece 1.
5. I didn't rewrite the VM, vault and lights code. I ran the real binary in `gdb`, put a breakpoint on `memcmp` and printed the first argument (`x/10xb $rdi`). That's the value the program wants for the next piece.
6. I repeated this 4 times, each time putting the new piece in the flag and zeros for the rest. This gave pieces 1 to 4.
7. I ran the full flag with `./encore verify`. All 5 cues said synchronized and the exit code was 0. The program also does a final hash check on the whole flag, so it's not a fake string.

## Flag
`GPI{2372f289d37d29394982046737216602f8fd12f117c9af5ebe37dbcd43bc6a66d4fab5cd9ad24905e3ad427e2f896afde869}`

`./encore verify` checks the same 108 character body under its own prefix, so locally the program wants `ENCORE{2372f289d37d29394982046737216602f8fd12f117c9af5ebe37dbcd43bc6a66d4fab5cd9ad24905e3ad427e2f896afde869}` and exits 0. The scoreboard takes the `GPI{...}` wrapper around that body.

## Tools used
- objdump, od, strings
- gdb
- Python 3

Evidence: [full solve output](evidence/solve_output.txt)
