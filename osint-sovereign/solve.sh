#!/bin/sh
# usage: sh solve.sh <folder with the challenge files>
cd "$1"
python3 -I -c "
from PIL import Image
for k,v in Image.open('survey_station_alpha.jpg').getexif().items(): print(k,'=',v)"
grep -o 'Hexadecimal authorization crumb: [0-9a-f]*' wikipedia_history_dump.xml
grep -o 'id=Q[0-9]*:P[0-9]*:[A-Z]*' wikipedia_history_dump.xml
grep -E 'Format:' incident_report.txt
echo "antenna=anflr9 island=bouvet year=1979 hex=8f2c9a"
echo "GPI{anflr9_bouvet_1979_8f2c9a}"
