# HAMLA_HO_GAYA
**Category:** Forensics | **Difficulty:** Medium | **Points:** 100 | **Solves:** 167

## What the challenge was
We got three files: `logs.txt`, `traffic.pcap` and `memory.mem`. The flag is split across all three, so I had to join the clues from each file.

## How I solved it
1. I unzipped the package and checked the files. ([evidence/01_files.txt](evidence/01_files.txt))
2. In `logs.txt` almost all lines are noise (health check and IIS). Only 10 lines are `SSH Login failure`. ([evidence/03_logs.txt](evidence/03_logs.txt))
3. The milliseconds of those 10 lines are `070 076 065 071 123 084 049 109 051 095`. As ASCII this is `FLAG{T1m3_`.
4. I parsed `traffic.pcap` by hand with Python. There are 4 requests to `/api/v1/telemetry_status`. Their `session_id` cookies are `Zmww`, `dzVf`, `MW50`, `MF8=`. In capture order, base64 decode gives `fl0` `w5_` `1nt` `0_` = `fl0w5_1nt0_`.
5. The same requests have `auth_token=42` every time. I kept this number because it looked like a key.
6. `memory.mem` is 8 MB of random data. I found a plain `FLAG{m3m0ry_f0r3n51c5_m45t3r}` at `0x500000`. I used it as the last part, but the site said it was wrong. It was a decoy. The plain `FLAG{h1dd3n_1n_pl41n_51ght}` in the pcap HTML is also a decoy.
7. There's a marker `[PAYLOAD_END]` at `0x60002a`. I took the bytes from `0x600000` up to it (42 bytes).
8. I tried the known word `m3m0ry` on the payload. At offset 30 the key came out as `******`, which is byte 42 (0x2a), the same as `auth_token`. ([evidence/04_decoys_and_crib.txt](evidence/04_decoys_and_crib.txt))
9. XOR the payload with 42. The first 30 bytes are random junk, and the end is `m3m0ry_v01d}`.
10. I joined the 3 parts with `python3 -I solve.py <folder>`. ([evidence/02_solve_output.txt](evidence/02_solve_output.txt))

I didn't decode the 55 extra bytes at the end of `memory.mem`. The flag was complete without them.

## Flag
`FLAG{T1m3_fl0w5_1nt0_m3m0ry_v01d}`

(Accepted by the CTF site.)

## Tools used
- unzip, grep
- Python 3 (struct, re, base64)
