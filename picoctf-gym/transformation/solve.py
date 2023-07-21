# ''.join([chr((ord(flag[i]) << 8) + ord(flag[i + 1])) for i in range(0, len(flag), 2)])

with open('enc', 'r') as f:
    encrypted_flag = f.read()

flag = []
for c in encrypted_flag:
    unicode = ord(c)
    ascii1 = unicode >> 8
    ascii2 = unicode & 0xFF
    flag.append(chr(ascii1))
    flag.append(chr(ascii2))

print(''.join(flag))