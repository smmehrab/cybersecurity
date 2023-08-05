import string

LOWERCASE_OFFSET = ord("a")
ALPHABET = string.ascii_lowercase[:16]

def b16_decode(enc_b16):
    n = len(enc_b16)
    dec = ""

    for i in range(0, n, 2):
        bleft = ALPHABET.index(enc_b16[i])
        bright = ALPHABET.index(enc_b16[i + 1])
        binary = "{0:04b}{1:04b}".format(bleft, bright)
        dec += chr(int(binary, 2))

    return dec

def rshift(c, k):
    t1 = ord(c) - LOWERCASE_OFFSET
    t2 = ord(k) - LOWERCASE_OFFSET
    shifted = ALPHABET[(t1 - t2) % len(ALPHABET)]
    return shifted

with open("ciphertext.txt", "r") as f:
    enc = f.read()

for k in ALPHABET:
    enc_b16 = ""
    for i, c in enumerate(enc):
        enc_b16 += rshift(c, k)

    dec = b16_decode(enc_b16)

    print(dec)
