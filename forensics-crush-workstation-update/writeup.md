# CRUSH WORKSTATION UPDATE
**Category:** Forensics | **Difficulty:** Hard | **Points:** 50 | **Solves:** 18

## What the challenge was
A workstation was seized after a big data upload. I had to find 8 facts (insider, alias, tool, domain, date, time, size, case ID), build the string `DARK_LEDGER_...` and give its MD5 as the flag. The files have fake flags and fake timestamps on purpose.

## How I solved it
1. I joined the 6 split parts with `cat` and unzipped twice. Inside were logs, a pcap, a USB image, a memory dump and phone databases.
2. In `Security.json` the PowerShell event used `-EncodedCommand`. I decoded it (base64, UTF-16): `MEGASYNC.exe sync C:\Vault\ CDN-LEDGER.INVALID:/leak ...`. User was `cferguson`. This gave the tool and the domain.
3. `employee_list.csv` maps `cferguson` to Christine Ferguson, so the insider is CHRISTINE_FERGUSON.
4. In `messages.db` (SQLite) a message says the board will publish notice under EXFILKING. The memory dump chat and the leak site also say EXFILKING.
5. The USB image looked like `zzzz...`. Zero bytes became `z` (0x7a), so I XORed the whole file with 0x7a. It became a tar file. `exfil_plan.enc` was XOR 0x33 and then base64. It said `CASE-3714`.
6. In the pcap one packet was XORed with 0x42. Decoded, it was an HTTP POST to CDN-LEDGER.INVALID with `Content-Length: 316669952`. That's 302.0 MiB, so 302MB. `X-Session-Auth` was base64 of `CASE-3714` too.
7. The time `2026-09-28T07:52:32` appears in 9 files (cloud audit, MFT, USN, Amcache, Prefetch, LNK, Security.json, zeek and storage log). The "+12m" clock event happens at 08:04, after the upload, and is marked as decoy, so I ignored it.
8. I joined the 8 fields with underscores and took the MD5. I had also made a version with no separators, but the platform accepted the underscore version.

String: `DARK_LEDGER_CHRISTINE_FERGUSON_EXFILKING_MEGASYNC.EXE_CDN-LEDGER.INVALID_2026-09-28_07-52-32_302MB_CASE-3714`

## Flag
`GPI{8693ed3b5531e91f0b24e27b814f6baa}`

## Tools used
- cat, unzip, base64, strings
- Python 3 (zipfile, sqlite3, tarfile)

Evidence: [solve output](evidence/solve_output.txt)
