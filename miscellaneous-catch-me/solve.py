import base64

# The two real halves, copied from the console table (button 17 and button 37)
part1 = "R1BJe1RIME5LWU9VX0QxUk"   # button 17
part2 = "xJTkdfVDBfRjhJTkRfTTF9"   # button 37

def b64(s):
    return base64.b64decode(s + "=" * (-len(s) % 4))

print("part1 alone :", b64(part1))
print("part2 alone :", b64(part2))
print("joined      :", b64(part1 + part2).decode())
