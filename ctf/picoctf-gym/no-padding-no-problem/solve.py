with open('value', 'r') as file:
    lines = [line.strip() for line in file]

n = int(lines[0].split(': ')[1])
e = int(lines[1].split(': ')[1])
c1 = int(lines[2].split(': ')[1])

print("n:", n)
print("e:", e)
print("c1:", c1)

p2 = int(input("\nEnter p2:\n"))

c2 = pow(p2, e, n)

c1c2 = (c1 * c2) % n

print("\nc1c2:", c1c2)

decrypted_c1c2 = int(input("\nEnter decrypted c1c2:\n"))

p1 = hex((decrypted_c1c2) // p2)

#Convert this to ASCII
print("\np1:\n", p1)
