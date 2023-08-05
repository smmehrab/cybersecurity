from Crypto.Util.number import long_to_bytes, inverse

# Open the file for reading
with open('value', 'r') as file:
    # Read the lines and strip any leading/trailing whitespace
    lines = [line.strip() for line in file]

# Extract the values from the lines
c = int(lines[0].split(': ')[1])
n = int(lines[1].split(': ')[1])
e = int(lines[2].split(': ')[1])
p = int(lines[3].split(': ')[1])
q = int(lines[4].split(': ')[1])

# Print the variables to verify
print("c:", c)
print("n:", n)
print("e:", e)
print("p:", p)
print("q:", q)

# totient function
phi = (p-1)*(q-1)

# Calculate the private key component
d = inverse(e, phi)

# Decrypt the ciphertext
pt = pow(c, d, n)

# Convert the decrypted plaintext to string
flag = long_to_bytes(pt).decode()

print("Flag:", flag)
