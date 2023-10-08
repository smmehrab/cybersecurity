# l = n - (p+q) + 1
# l = split + (p+q) - 3
# l = (n + split - 2) // 2

from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes

# Read the values from your code
ciphertext = 64059041051643141423589456488253364432179353193695619490257971693099941278147
n = 77877452723568809002786058317114185337930223566249526469010813218796208203291
e = 65537
split = 77877452723568809002786058317114185336797844222164545001194029991785424890375

# Calculate l
l = (n + split - 2) // 2

# Calculate d
d = inverse(e, l)

# Print the calculated values
print('ciphertext:', ciphertext)
print('n:', n)
print('e:', e)
print('split:', split)
print('l:', l)
print('d:', d)

# Calculate the plaintext integer
plaintext_int = pow(ciphertext, d, n)

# Convert the plaintext integer to bytes
plaintext_bytes = long_to_bytes(plaintext_int)

# Print the plaintext bytes
print('plaintext:', plaintext_bytes)



