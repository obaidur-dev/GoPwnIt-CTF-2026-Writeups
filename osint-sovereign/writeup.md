# Sovereign
**Category:** OSINT | **Difficulty:** Medium | **Points:** 50 | **Solves:** 127

## What the challenge was
A Wikipedia editor called SovereignCartographer left an incident log, an XML edit dump and a photo. I had to build the flag from them.

## How I solved it
1. I read `incident_report.txt`. It gives the flag format: `GPI{<antenna_code>_<target_island>_<incident_year>_<hex_auth>}`. ([evidence/incident_report.txt](evidence/incident_report.txt))
2. I read the EXIF of the photo with PIL. It says station AN/FLR-9, target Bouvet, event 1979, hash 8f2c9a. I also enhanced the picture and found no hidden text. ([evidence/exif.txt](evidence/exif.txt))
3. In the XML, the reverted edit on "Bouvet Island" has a citation with `id=Q31057:P625:WULLENWEBER` and `Hexadecimal authorization crumb: 8f2c9a`. Q31057 is Bouvet Island. ([evidence/xml_grep.txt](evidence/xml_grep.txt))
4. So the parts are: antenna AN/FLR-9, island Bouvet, year 1979 (the Vela flash), hex 8f2c9a.
5. The MD5 in the report doesn't match the jpg. I ignored it.
6. My first guesses at the antenna and island spelling (`AN-FLR-9`, `FLR-9`, etc.) were rejected by the platform. The accepted form removes the symbols from `AN/FLR-9` to get `ANFLR9`, and the whole flag body must be lowercase. ([evidence/solve_output.txt](evidence/solve_output.txt))

## Flag
`GPI{anflr9_bouvet_1979_8f2c9a}`

## Tools used
- python3 + PIL (EXIF, image check)
- grep
