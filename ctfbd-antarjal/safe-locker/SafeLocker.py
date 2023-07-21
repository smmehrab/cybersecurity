from Crypto.Util.number import getStrongPrime, isPrime, inverse, bytes_to_long

flag = open('flag.txt', 'r').read()

while True:
	q = getStrongPrime(512)
	p = 2*q + 1

	if (isPrime (p)):
		break

n = p*q
phi = (p-1)*(q-1)
e = 65537
d = inverse (e, phi)

pt = bytes_to_long(flag.encode())
ct = pow(pt,e,n)


content = f"e: {e}\nphi: {phi}\nct: {ct}"

with open('output.txt', 'w') as file:
    file.write(content)