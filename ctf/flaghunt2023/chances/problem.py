from random import randint

flag = open('flag.txt', 'rb').read()

def to_bits(c):
    b = bin(c)[2:]
    while len(b) != 8:
        b = '0' + b
    return b


bits = ''.join([to_bits(c) for c in flag])

distorted = []

for _ in range(50):
    d = ''
    for b in bits:
        r = randint(1, 10)
        if r <= 3:
            b = int(b) ^ 1
        d += str(b)
    distorted.append(d)

with open('out.txt', 'w') as f:
    to_write = '\n'.join(distorted)
    f.write(to_write)