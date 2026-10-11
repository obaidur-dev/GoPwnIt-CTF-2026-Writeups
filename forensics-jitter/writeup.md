# Jitter
**Category:** Forensics | **Difficulty:** Medium | **Points:** 100 | **Solves:** 62

## What the challenge was
A host pings one outside address all day. I got a 20 minute capture (`ping.pcap`) and had to find what was hidden in it.

## How I solved it
1. I read the pcap with scapy. It has 4400 packets. Two hosts send pings: `10.20.0.57 -> 192.0.2.9` (1300 requests) and `10.20.0.99 -> 192.0.2.50` (500 requests). The DNS packets looked like noise. ([evidence/pcap_overview.txt](evidence/pcap_overview.txt))
2. The gaps between the 1300 pings are either about 1.0 s or about 1.25 s. I took long = 1 and short = 0 and turned the bits into bytes.
3. That gave a note: the IP-ID low byte of each request holds `u16be L, nonce[12], AES-256-GCM` and the key is `SHA256('TIDEMARK-0619')`.
4. The TTL is 64 or 65. I decoded that too (65 = 1) and got `GPI{ttl_b1ts_4r3_th3_cl3v3r_0n3_r1ght_d913}`. This looked like a fake flag, because the timing note pointed to a different channel.
5. I took the low byte of the IP-ID of each request. First 2 bytes = length 85, next 12 bytes = nonce, then the ciphertext.
6. I tried different split points for ciphertext and the 16 byte tag. At 57 bytes the GCM tag was valid, so the decrypt is real. Script: `python3 -I solve.py ping.pcap` ([evidence/solve_output.txt](evidence/solve_output.txt)).

## Flag
`GPI{th3_p4yl04d_w4s_n01s3_th3_g4ps_w3r3_th3_m3ss4g3_d5b0}`

## Tools used
- python3, scapy
- pycryptodome (AES-GCM)
