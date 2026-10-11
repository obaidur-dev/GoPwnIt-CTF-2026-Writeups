import sys,re
from sympy import factorint, isprime
t=open(sys.argv[1]).read()
p=int(re.search(r'p = (0x\w+)',t).group(1),16)
print(p.bit_length(), isprime(p))
f=factorint(p-1,limit=2**40)
print(f)
