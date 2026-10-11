# ARGON The Silent Vault
**Category:** Cryptography | **Difficulty:** Hard | **Points:** 150 | **Solves:** 90

## What the challenge was
A signing device leaked the top 12 bits of the nonce `k` for each of 96 ECDSA (secp256k1) signatures. I had to get the private key, open `recovery.enc`, then open `vault.enc`.

## How I solved it
1. I unzipped the package and read `challenge.py`. It showed the file formats and the key steps (HKDF, RSA, Argon2id). The diagnostic file gives `k >> 244` for each signature.
2. I checked that all 96 signature ids match the 96 records in `diagnostics.bin` (channel 0x42). They did.
3. This is a Hidden Number Problem. From `s*k = z + r*d (mod n)` I wrote `k = t*d + a` with `t = r/s` and `a = z/s`. Since `k = h*2^244 + x` and `x < 2^244`, each signature gives one small-unknown equation.
4. I built a lattice with those 96 equations and ran LLL and then BKZ (block size 20) using fpylll: `python3 -I solve1_hnp.py pkg` (about 10 seconds).
5. The short vector gave `d`. I checked it by computing `d*G` and comparing with the public key Q. It matched.
   `d = 0xeece93923506b3f32b4212b72a7fa5094a411becd06d2d00ce7452d4223a050c`
6. I made the key with HKDF-SHA256 (salt from `public.json`, info `ARGON/RECOVERY/v1`) and decrypted `recovery.enc` with AES-GCM: `python3 -I solve2_recovery.py pkg`. Inside was an RSA payload with e1=65537, e2=100003, c1 and c2 for the same N.
7. Common modulus attack. With extended Euclid I got `-20737*e1 + 13590*e2 = 1`, so `m = c1^-20737 * c2^13590 mod N`. I checked that `m^e1 = c1` and `m^e2 = c2`. This gave the 32 byte token T.
8. I made the vault key: Argon2id (64 MiB, 3 passes, 4 lanes) over `SHA256("ARGON/FINAL/v1" || d || T)`. Then I decrypted `vault.enc` with AES-GCM: `python3 -I solve3_vault.py pkg`. The tag passed and the flag came out.

The three scripts run in order and hand state to each other through `d.txt` and `bundle.json`, which they write next to the `pkg/` folder, so keep the challenge files one level down:

```
mkdir -p argon && cd argon
python3 -I ../solve1_hnp.py pkg
python3 -I ../solve2_recovery.py pkg
python3 -I ../solve3_vault.py pkg
```

- [HNP output](evidence/01_hnp_recover_d.txt)
- [recovery bundle](evidence/02_decrypt_recovery.txt)
- [RSA and vault](evidence/03_rsa_and_vault.txt)

## Flag
`GPI{argon_d5e6376be1105fffc0e40e9ffcf08f52}`

## Takeaway
Partial nonce leakage is a full key recovery. Twelve bits per signature sounds like nothing until you stack 96 of them into a lattice and the private key falls out in ten seconds.

## Tools used
- Python 3
- fpylll (LLL / BKZ)
- cryptography (HKDF, AES-GCM)
- argon2-cffi
