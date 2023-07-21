from Crypto.Util.number import long_to_bytes

# Read the contents from the output file
with open('output.txt', 'r') as file:
    content = file.read()

# Parse the values from the content
e, phi, ct = [int(val.split(': ')[1]) for val in content.split('\n')[0:3]]

# Calculate the private key component
d = inverse(e, phi)

# Decrypt the ciphertext
pt = pow(ct, d, n)

# Convert the decrypted plaintext to string
flag = long_to_bytes(pt).decode()

print("Flag:", flag)
