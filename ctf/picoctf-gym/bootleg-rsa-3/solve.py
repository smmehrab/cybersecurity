from Crypto.Util.number import *

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

    # https://www.alpertron.com.ar/ECM.HTM
    prime_factors = [9116907323, 9423770959, 9507349459, 9729056629, 9806700247, 9845954003, 10149104747, 10353560089, 10474878587, 10628885107, 10759110179, 10788363577, 10893258907, 11170311989, 11341865347, 11386011449, 11675180449, 11675253311, 11726826329, 12229962229, 12449633363, 12767287913, 13057357519, 13316938163, 13503053731, 13578431689, 13783236317, 14304001529, 14331692363, 14822617699, 15240992119, 15253150931, 15856217561, 15869057327]
    phi = 1
    for p in prime_factors:
        phi *= (p - 1)
    
    print(f"phi: {phi}")

    d = inverse(e, phi)

    print(f"d: {d}")

    p = pow(c, d, n)
    p = to_ascii(p)
    print(f"p: {p}")
