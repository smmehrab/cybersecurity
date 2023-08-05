from decimal import *

def to_ascii(x):
    """
        int --> hex --> ascii
    """
    x_hex = hex(int(x))[2:-1]
    x_hex_len = len(x_hex)
    x_ascii = "".join(chr(int(x_hex[i : i + 2], 16)) for i in range(0, x_hex_len, 2))
    return x_ascii.strip()

def inv_pow(b, p):
    """
        b is very large
    """

    b = Decimal(b)
    p = Decimal(p)
    getcontext().prec = 500
    return pow(b, 1/p)

if __name__ == "__main__":

    # Open the file for reading
    with open('value', 'r') as file:
        # Read the lines and strip any leading/trailing whitespace
        lines = [line.strip() for line in file]

    # Extract the values from the lines
    N = int(lines[0].split(': ')[1])
    e = int(lines[1].split(': ')[1])
    c = int(lines[2].split(': ')[1])

    print(f"N: {N}")
    print(f"e: {e}")
    print(f"c: {c}")

    brute_force_limit = 40000
    for k in range(40000):
        print(f"k: {k}")
        p = inv_pow(((k * N) + c), e)
        p = to_ascii(p)
        if "pico" in p or "CTF" in p:
            print(f"p: {p}")
            break

    print("Success!")
