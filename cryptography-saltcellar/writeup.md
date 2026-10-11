# Saltcellar
**Category:** Cryptography | **Difficulty:** Medium | **Points:** 100 | **Solves:** 52

## What the challenge was
Forty ECDSA signatures on secp256k1. The nonce is `k = STEP * random192`, so it's always a multiple of a known number. The flag is encrypted with a hash of the private key `d`. ([files](evidence/01_files.txt))

## How I solved it
1. I read `signer.py`. The nonce is `STEP * secrets.randbits(192)`, and `STEP = 0x9E3779B97F4A7C15`.
2. ECDSA gives `s*k = h + r*d (mod n)`. Put `k = STEP*m` and I get `m = A + B*d (mod n)`, where `A = (STEP*s)^-1 * h` and `B = (STEP*s)^-1 * r`.
3. `m` is only 192 bits but `n` is 256 bits. So every signature leaks 64 bits. This is a hidden number problem.
4. I built a lattice from the first 10 signatures, with `d` and a constant in the last two columns. I centred `m` first by subtracting 2^191.
5. I reduced it with LLL and then BKZ (block size 20) using fpylll. I looked for the row with the constant `2^256` in the last column.
6. I took `d` from the row. I checked `d*G` against the public key, and it matched.
7. I made the key `sha256(d.to_bytes(32,"big"))` and XORed it with `flag.enc`. 10 signatures were enough. ([output](evidence/02_solve_10_sigs.txt))
   `python3 -I solve.py handout 10`

`d = 0x5005554fa55b9e811a71e69c7caa0ad95768469ef5e8b363b363b2a77dfddc2f`

## Flag
`GPI{th3_b14s_w4s_4_mult1pl3_n0t_4_sh1ft}`

## Tools used
- Python 3 (own EC point code)
- fpylll (LLL / BKZ)
