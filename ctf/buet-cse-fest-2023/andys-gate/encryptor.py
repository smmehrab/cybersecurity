import random

def reverse_andys_gate(ciphertext, key_length):
    result = 0
    bit_pos = 0

    while ciphertext > 0:
        andys_bit = (ciphertext >> bit_pos) & 1

        a = 0
        b = 0
        shift = 0

        for i in range(bit_pos, bit_pos + key_length):
            a_bit = (a >> shift) & 1
            b_bit = (b >> shift) & 1
            a |= (a_bit ^ (andys_bit & b_bit)) << shift
            b |= (b_bit ^ (andys_bit & a_bit)) << shift
            shift += 1

        decrypted_bit = a & 1
        result += decrypted_bit << bit_pos
        bit_pos += 1
        ciphertext >>= key_length

    return result


def andys_gate(a, b):
    result = 0
    bit_pos = 0

    while a > 0 or b > 0:
        lsb_a = a % 2
        lsb_b = b % 2
        andys_bit = not(not(lsb_a and not(lsb_a and lsb_b)) and not(lsb_b and not(lsb_a and lsb_b)))
        result += andys_bit << bit_pos
        bit_pos += 1
        a >>= 1
        b >>= 1

    return result

def encrypt(flag):
    padding_length = random.randint(1, 50)
    padding_text = "0" * (padding_length - (len(flag) % padding_length))
    
    if(len(flag) % padding_length != 0):
        flag += padding_text
    
    encrypted = ""

    for i in range(0, len(flag)-padding_length, padding_length):
        encrypted += "".join(chr(andys_gate(ord(a), ord(b))) for a,b in zip(flag[i:i+padding_length], flag[i+padding_length:i+2*padding_length]))

    encrypted += "".join(chr(andys_gate(ord(a), ord(b))) for a,b in zip(flag[-padding_length:], "0" * padding_length))
    return encrypted

print(andys_gate(20, 40))

# flag = open("flag.txt", "r").read()

# encrypted = encrypt(flag)

# with open("encrypted", "wb") as f:
#     f.write(bytes(encrypted, "utf-32"))