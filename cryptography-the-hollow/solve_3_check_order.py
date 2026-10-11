import re,sys
t=open(sys.argv[1]).read()
p=int(re.search(r'p = (0x\w+)',t).group(1),16);g=2
y=int(re.search(r'y = (0x\w+)',t).group(1),16)
fs=[2,2039,4049,9203,10847,12413,21521,28813,37549,39821,43577,44687,48989,50651,50929,54091,57251,136973113,754799435023,1228410153261862865464230587769556123390808322427078055105669]
n=p-1
from math import prod
assert prod(fs)==n
for q in fs:
    print(q if q<10**12 else 'BIG', pow(g,n//q,p)!=1, pow(y,n//q,p)!=1)
