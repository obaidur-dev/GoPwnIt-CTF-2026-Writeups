# Candle Wright
**Category:** Cryptography | **Difficulty:** Easy | **Points:** 50 | **Solves:** 176

## What the challenge was
We got one file, `intercept.txt`, with a base64 blob. It's a memo that says the flag is hidden inside it. `check.py` tells if a flag is right.

## How I solved it
1. I base64 decoded the blob. It was 1491 bytes and looked random.
2. I checked repeating key length with index of coincidence. Length 9 gave 0.0612, other lengths gave about 0.01 (also 18, which is just 2x9). So it's a 9 byte repeating XOR key. See [evidence/solve_output.txt](evidence/solve_output.txt).
3. I cracked each of the 9 key bytes by trying all 256 values and scoring how much English text came out. Key bytes: `[192, 18, 151, 152, 120, 18, 11, 82, 189]`.
4. The memo came out as plain English. It gives an "operator code" `GPI{r3p34t1ng_k3ys_n3v3r_r3p34t_3n0ugh}`. The memo says twice this isn't the flag. `check.py` also rejected it.
5. The memo gives steps for the real key: keep only the letters of the operator code, shift the i-th letter forward by i (first letter is 1), lowercase. I got `srwrlqfawfcdchckxz`.
6. The sealed line at the bottom is XORed with the SHA-256 of that key, repeated. I decrypted it and got `dispatch flag: GPI{...}`.
7. I first gave `check.py` the whole line with `dispatch flag: ` in front and it said rejected. I removed the label and it said accepted. See [evidence/check_output.txt](evidence/check_output.txt).
8. All of this is in one script: `python3 solve.py intercept.txt`

## Flag
`GPI{r34d_th3_m3m0_n0t_just_th3_br4c3s}`

## Tools used
- Python 3 (base64, hashlib)
- check.py from the challenge
