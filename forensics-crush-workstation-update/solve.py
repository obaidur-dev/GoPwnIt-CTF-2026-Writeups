#!/usr/bin/env python3
# usage: python3 solve.py <folder with the 6 split parts .zip.001-.006> <work dir>
import sys, os, glob, zipfile, io, json, csv, base64, struct, sqlite3, hashlib, tarfile
src, work = sys.argv[1], sys.argv[2]
os.makedirs(work, exist_ok=True)
# 1) join the split parts, unzip twice
parts = sorted(glob.glob(f'{src}/*player_package_split.zip.00?'), key=lambda p: p[-3:])
blob = b''.join(open(p,'rb').read() for p in parts)
outer = zipfile.ZipFile(io.BytesIO(blob)); print('outer:', outer.namelist())
inner = zipfile.ZipFile(io.BytesIO(outer.read(outer.namelist()[0]))); ev = f'{work}/ev'; inner.extractall(ev)
print('inner files:', len(inner.namelist()))
# 2) insider: user that ran the powershell/MEGASYNC events
sec = json.load(open(f'{ev}/workstation_artifacts/Windows_Event_Logs/Security.json'))
ps = [e for e in sec if e['EventID']==4688 and 'powershell' in e['Data']['NewProcessName'].lower()][0]
print('powershell event:', ps['TimeCreated'], ps['Data']['SubjectUserName'])
cmd = base64.b64decode(ps['Data']['CommandLine'].split('-EncodedCommand ')[1]).decode('utf-16le'); print('decoded command:', cmd)
user = ps['Data']['SubjectUserName']
for r in csv.DictReader(open(f'{ev}/employee_list.csv')):
    if r['Username']==user: print('employee list:', r)
tool, domain = cmd.split()[0].upper(), cmd.split()[3].split(':')[0].upper()
# 3) alias from SMS
c = sqlite3.connect(f'{ev}/mobile_backup/messages.db')
for row in c.execute("select body from message where body like '%publish%'"): print('sms:', row[0])
alias = 'EXFILKING'
# 4) USB image is XOR 0x7a (tar). exfil_plan.enc is XOR 0x33 then base64
usb = bytes(b^0x7a for b in open(f'{ev}/usb_image/suspicious_usb.img','rb').read())
tf = tarfile.open(fileobj=io.BytesIO(usb)); print('usb files:', tf.getnames())
plan = base64.b64decode(bytes(b^0x33 for b in tf.extractfile('.vault_sync/exfil_plan.enc').read())).decode(); print('exfil plan:', plan)
case = plan.split('tracking assigned as ')[1].split('.')[0]
# 5) pcap: find the http POST packet (XOR 0x42), read Content-Length and session auth
d = open(f'{ev}/network/network_capture.pcapng','rb').read(); off = 24
while off+16 <= len(d):
    cl = struct.unpack('<I', d[off+8:off+12])[0]; pkt = d[off+16:off+16+cl]; off += 16+cl
    ihl = (pkt[14]&15)*4
    if pkt[23]==6:
        p = pkt[14+ihl+((pkt[14+ihl+12]>>4)*4):]
        if p[:1]==b'\x12' and len(p)<400:
            http = bytes(b^0x42 for b in p).decode(); print('pcap packet (xor 0x42):\n'+http)
            size = int([l for l in http.splitlines() if l.startswith('Content-Length')][0].split(': ')[1])
            print('X-Session-Auth decoded:', base64.b64decode([l for l in http.splitlines() if 'Session-Auth' in l][0].split(': ')[1]).decode())
print('size MB =', size/1048576)
# 6) time: same value in many artifacts
import re, subprocess
hits = subprocess.run(f"grep -rl '2026-09-28T07:52:32' {ev} | sort", shell=True, capture_output=True, text=True).stdout
print('files with 2026-09-28T07:52:32:\n'+hits)
name = [r for r in csv.DictReader(open(f'{ev}/employee_list.csv')) if r['Username']==user][0]['Name'].upper().replace(' ','_')
s = '_'.join(['DARK_LEDGER_'+name, alias, tool, domain, '2026-09-28', '07-52-32', f'{size//1048576}MB', case])
print('string:', s); print('flag: GPI{%s}' % hashlib.md5(s.encode()).hexdigest())
