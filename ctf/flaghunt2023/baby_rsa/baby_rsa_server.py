#!/usr/local/bin/python

from Crypto.Util.number import getPrime, bytes_to_long as b2l, long_to_bytes as l2b

print("Welcome to delphi's query service!!")

primes = [getPrime(512) for _ in range(10)]

with open('flag.txt', 'rb') as f:
    flag = f.read()

m = b2l(flag)
assert(m.bit_length() > 1200 and m.bit_length() < 2000)

used_indices = set()
for _ in range(5):
    print('Enter 2 indices for primes to be used for RSA (eg. 0 4): ')
    i, j = map(int, input().split())

    if i in used_indices or j in used_indices or i < 0 or j < 0 or i == j:
        print('Illegal values given!!')
        exit(2)

    i, j = i % 10, j % 10

    used_indices.add(i)
    used_indices.add(j)

    p, q = primes[i], primes[j]
    n = p * q
    e = 0x10001 # 65537
    ct = pow(m, e, n)

    print('n = ', n)
    print('ct = ', ct)