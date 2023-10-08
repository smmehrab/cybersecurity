from collections import Counter

def from_bits(b):
    return chr(int(b, 2))

with open('out.txt', 'r') as f:
    distorted = f.read().split('\n')

# Transpose the list of strings
transposed = list(map(list, zip(*distorted)))

# For each position, count the occurrences of '0' and '1'
counts = [Counter(bits) for bits in transposed]

# Choose the most common bit at each position
recovered_bits = [max(bits, key=bits.get) for bits in counts]

# Group the bits into bytes and convert back to characters
flag = ''.join([from_bits(''.join(recovered_bits[i:i+8])) for i in range(0, len(recovered_bits), 8)])

print(flag)
