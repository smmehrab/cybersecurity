def to_ascii(x):
    """
        int --> hex --> ascii
    """
    x_hex = hex(int(x))[2:-1]
    x_hex_len = len(x_hex)
    x_ascii = "".join(chr(int(x_hex[i : i + 2], 16)) for i in range(0, x_hex_len, 2))
    return x_ascii.strip()

if __name__ == "__main__":

    # Open the file for reading
    with open('value', 'r') as file:
        # Read the lines and strip any leading/trailing whitespace
        lines = [line.strip() for line in file]

    # Extract the values from the lines
    c = int(lines[0].split(': ')[1])
    n = int(lines[1].split(': ')[1])
    e = int(lines[2].split(': ')[1])

    print(f"c: {c}")
    print(f"n: {n}")
    print(f"e: {e}")

    for d in range(1, 100000):
        print(f"d: {d}")
        p = pow(c, d, n)
        p = to_ascii(p)
        if "pico" in p or "CTF" in p:
            print(f"p: {p}")
            break

    print("Success!")
