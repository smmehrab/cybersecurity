from functools import reduce
from pwn import *
from Crypto.Util.number import long_to_bytes as l2b, GCD, isPrime

io = remote('45.76.177.238', 5001)

io.recvline()
io.recvline()
io.sendline(b'0 1')

n1 = int(io.recvline().decode().strip().split('= ')[1])
ct1 = int(io.recvline().decode().strip().split('= ')[1])

io.recvline()
io.sendline(b'11 2')

n2 = int(io.recvline().decode().strip().split('= ')[1])
ct2 = int(io.recvline().decode().strip().split('= ')[1])

io.recvline()
io.sendline(b'3 4')

n3 = int(io.recvline().decode().strip().split('= ')[1])
ct3 = int(io.recvline().decode().strip().split('= ')[1])

io.recvline()
io.sendline(b'14 5')

n4 = int(io.recvline().decode().strip().split('= ')[1])
ct4 = int(io.recvline().decode().strip().split('= ')[1])

print('[+] Params collection done')

def crack(N1, N2):
    p1 = GCD(N1, N2)
    p2 = p1
    q1 = N1 // p1
    q2 = N2 // p2
    assert(isPrime(p1) and isPrime(p2)  and isPrime(q1) and isPrime(q2))
    phi1, phi2 = (p1 - 1) * (q1 - 1), (p2 - 1) * (q2 - 1)
    e = 0x10001
    d1, d2 = pow(e, -1, phi1), pow(e, -1, phi2)
    return d1, d2

d1, d2 = crack(n1, n2)
m1, m2 = pow(ct1, d1, n1), pow(ct2, d2, n2)

d3, d4 = crack(n3, n4)
m3, m4 = pow(ct3, d3, n3), pow(ct4, d4, n4)

print('[+] Cracking done.. Will start doing the CRT')

def chinese_remainder(n, a):
    sum = 0
    prod = reduce(lambda a, b: a*b, n)
    for n_i, a_i in zip(n, a):
        p = prod // n_i
        sum += a_i * pow(p, -1, n_i) * p
    return sum % prod

def mul_inv(a, b):
    return pow(a, -1, b)

msg = chinese_remainder([n1, n3], [m1, m3])
flag = l2b(msg)
print(flag)
