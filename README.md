# GoPwnIt CTF 2026 — Writeups

Writeups from **GoPwnIt CTF 2026**, an online Jeopardy-style CTF run by GoPwnIt on
10 October 2026.

| | |
|---|---|
| **Result** | 43 of 44 challenges solved (98%) |
| **Score** | 4,200 points |
| **Rank** | 9th |
| **Handle** | `otrix` |
| **Format** | Solo, online, 8 hours, no teams |
| **Challenges** | 44 across 8 categories |

I solved 43 of the 44 challenges. These are the 13 I wrote up properly — 1,200 points
worth. The remaining 30 were solved during the event and never written down. The one
I missed was `growupbaby` (Reverse Engineering, Medium, 12 solves).

---

## Writeups

| Challenge | Category | Difficulty | Points | Solves | |
|---|---|---|---|---|---|
| ARGON The Silent Vault | Cryptography | Hard | 150 | 90 | [writeup](cryptography-argon-the-silent-vault/writeup.md) |
| Candle Wright | Cryptography | Easy | 50 | 176 | [writeup](cryptography-candle-wright/writeup.md) |
| Saltcellar | Cryptography | Medium | 100 | 52 | [writeup](cryptography-saltcellar/writeup.md) |
| The Hollow | Cryptography | Hard | 150 | 43 | [writeup](cryptography-the-hollow/writeup.md) |
| CRUSH WORKSTATION UPDATE | Forensics | Hard | 50 | 18 | [writeup](forensics-crush-workstation-update/writeup.md) |
| HAMLA_HO_GAYA | Forensics | Medium | 100 | 167 | [writeup](forensics-hamla-ho-gaya/writeup.md) |
| Jitter | Forensics | Medium | 100 | 62 | [writeup](forensics-jitter/writeup.md) |
| Catch me | Miscellaneous | Medium | 50 | 51 | [writeup](miscellaneous-catch-me/writeup.md) |
| Ragebait | Miscellaneous | Hard | 50 | 55 | [writeup](miscellaneous-ragebait/writeup.md) |
| Sovereign | OSINT | Medium | 50 | 127 | [writeup](osint-sovereign/writeup.md) |
| college_crush | Reverse Engineering | Medium | 100 | 107 | [writeup](reverse-engineering-college-crush/writeup.md) |
| SHORTCUTS | Reverse Engineering | Medium | 100 | 96 | [writeup](reverse-engineering-shortcuts/writeup.md) |
| SHAKIRA The Broken Encore | Reverse Engineering | Hard | 150 | 43 | [writeup](reverse-engineering-the-broken-encore/writeup.md) |

Solves is how many people cleared it on the scoreboard, so it says more about how
obvious a challenge was than how hard it was. Candle Wright was the softest thing here
at 176 solves. CRUSH WORKSTATION UPDATE and The Hollow were the stingiest at 18 and 43.

---

## Things worth knowing before you read

A few of these challenges will waste your time if you don't know about it up front.

**Most of them hand you a fake flag.** More than one challenge ships a complete,
correctly formatted `GPI{...}` that the platform rejects. If a flag looks too clean,
read the Flag section of the writeup before you assume you solved it wrong.

- **Ragebait** has 18 `GPI{...}` strings in the binary. The one it makes the most noise
  about is the trap.
- **Candle Wright** gives you a plausible "operator code" in cleartext and tells you
  twice that it isn't the flag.
- **Jitter** decodes cleanly into a `GPI{...}` string straight out of the TTL bits. The
  real one is in the IP-ID field.
- **Catch me** has one of its two real halves decode to junk on its own.

**Three challenges use a prefix other than `GPI{...}`.** The binary checks its own
prefix, but the scoreboard takes the standard `GPI{...}` wrapper around the same body.

| Challenge | Binary accepts | Scoreboard takes |
|---|---|---|
| college_crush | `zplus{I_WaZ_Too_Lazy}` | `GPI{I_WaZ_Too_Lazy}` |
| SHAKIRA The Broken Encore | `ENCORE{2372f289...}` | `GPI{2372f289...}` |
| HAMLA_HO_GAYA | — | `FLAG{T1m3_fl0w5_1nt0_m3m0ry_v01d}` |

For SHORTCUTS the binary prints the bare 64 character key and never emits a wrapper at
all; the key is the flag body.

**college_crush is 21 bytes wide.** The comparison target includes the prefix, so
`GPI{...}` fails inside the exe no matter how correct the body is.

---

## Layout

Every challenge gets its own folder named `<category>-<challenge-name>`:

```
cryptography-argon-the-silent-vault/
├── writeup.md          the writeup
├── solve.py            the solver (or solve_1_, solve_2_, ... when it's multi-stage)
└── evidence/           output captured from an actual run
```

`evidence/` holds the real terminal output rather than a cleaned-up transcript, so you
can check my work. Some folders needed more than one script — those are numbered in the
order they run. Two extras:

- `reverse-engineering-college-crush/verify_emu.py` — I ran the binary's own VM in
  Unicorn to check my reading of it, after counting the `.zplus` bytes by hand and
  getting the wrong answer.
- `miscellaneous-ragebait/helpers/` — small scripts for reading the Go function table,
  disassembling `main.main`, and pulling the decoy list out of `.data`.

---

## Requirements

Everything is Python 3. The solvers don't share a virtualenv; most of them only need the
standard library.

```bash
pip install -r requirements.txt
```

Only install what the writeup you're running asks for — the list is the union across all
13. Notable ones:

| Package | Used by |
|---|---|
| `fpylll` | ARGON, Saltcellar (LLL / BKZ lattice reduction) |
| `sympy` | The Hollow (factoring, CRT) |
| `scapy`, `pycryptodome` | Jitter (pcap parsing, AES-GCM) |
| `pefile`, `capstone` | Ragebait, college_crush (PE parsing, disassembly) |
| `unicorn` | college_crush (`verify_emu.py`) |
| `py7zr` | college_crush (the handout is a 7-zip archive with a `.tgz` name) |
| `libarchive-c` | SHORTCUTS (`extract.py`, for the RAR5 handout) |
| `cryptography`, `argon2-cffi` | ARGON (HKDF, AES-GCM, Argon2id) |
| `pillow` | Sovereign (`solve.sh`, EXIF) |

A few solvers shell out to tools that need to be on `PATH`: `file`, `strings`, `objdump`,
`readelf`, `strace`, `unzip`, `gdb`. `miscellaneous-ragebait` needs `wine64` installed,
because the only way past its trap is to run the Windows binary for real.

Catch me was the only one here that depended on a live site, and that site is almost
certainly gone now. The rest are offline handouts you can still work through in full.

---

## Running a solver

Each writeup documents the exact command. Most take the path to the extracted challenge
folder:

```bash
python3 -I solve.py <challenge-folder>
```

ARGON is multi-stage and threads state between scripts through `d.txt` and
`bundle.json`, so keep its challenge files one level down and run all three in order.
SHAKIRA The Broken Encore needed a live `gdb` session against the real binary rather
than a static rewrite — the writeup has the breakpoint setup.

---

## Notes

- No challenge binaries are included here, only my solvers and their output. Everything
  here runs against the handout you get from the platform.
- Everything is documented as I actually did it, including the dead ends. A few writeups
  have a step where I got it wrong and say so — that's usually the interesting part.
- Thanks to GoPwnIt for putting on a clean event, and to the author team — 6 of these 13
  challenges are from `bhaiya_ji`, the other 7 from the GoPwnit core set.

---

## About

Written by **otrix**.

[![GitHub](https://img.shields.io/badge/GitHub-obaidur--dev-181717?style=for-the-badge&logo=github)](https://github.com/obaidur-dev)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-obaidur01-0A66C2?style=for-the-badge&logo=linkedin)](https://linkedin.com/in/obaidur01)
