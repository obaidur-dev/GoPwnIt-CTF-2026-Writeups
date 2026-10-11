# The Hollow
**Category:** Cryptography | **Difficulty:** Hard | **Points:** 150 | **Solves:** 43

## What the challenge was
Three MAC'd envelopes, an encrypted vault file (`stage2.bin`) and an encrypted flag. One 128-bit key `H` is used for the MAC and for the encryption. The vault is a discrete log problem.

## How I solved it
1. I read `notes.md` and `envelopes.txt`. All three envelopes use the same nonce, and each ciphertext is one 16-byte block. ([files](evidence/01_files.txt))
2. The tag is `B*H^2 + L*H + S` in GF(2^128). Same nonce means same `L` and `S`. If I XOR two tags, they cancel. I get `T_i ^ T_j = (B_i ^ B_j) * H^2`.
3. I divided to get `H^2`, then took the square root (`a^(2^127)`). All three pairs gave the same `H = d59d9939a0820f4dde7417d787839399`.
4. I checked it. The envelopes decrypt to `release batch 07`, `hold batch 07!!!`, `amend batch 07 x`, and all tags matched. ([output](evidence/02_recover_H.txt))
   `python3 -I solve_1_recover_H.py handout H.bin stage2.txt`
5. The same run decrypted `stage2.bin` with `sha256(H)`. It gave `p` (500 bits), `g = 2` and `y`.
6. I factored `p-1` with sympy. It's smooth except for one 200-bit prime. I checked that the big factors are really prime. ([factor](evidence/03_factor.txt), [prime check](evidence/03b_big_primes_check.txt))
   `python3 -I solve_2_factor.py stage2.txt`
7. I checked the order of `g` and `y`. Every factor divides both, so I couldn't skip the 200-bit prime. ([output](evidence/04_check_order.txt))
8. The other factors multiply to a 300-bit number `M`. I ran Pohlig-Hellman (baby-step giant-step for each small prime) and CRT. That gives `x mod M`.
9. The result `x` is 297 bits, smaller than `M`, so it's the real `x`. I checked `g^x == y`, which printed `True`.
10. I made the key `sha256(H_bytes || x_bytes)` and decrypted `flag.enc`. ([output](evidence/05_dlog_flag.txt))
    `python3 -I solve_4_dlog_flag.py handout stage2.txt H.bin flag.enc`

## Flag
`GPI{0n3_f0ld_k3y_tw0_j0bs_4nd_4_sm00th_pr1m3}`

## Tools used
- Python 3 (own GF(2^128) code, hashlib)
- sympy (factoring, CRT)
