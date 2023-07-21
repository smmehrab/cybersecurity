import random

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

def decrypt(encrypted):
    for padding_length in range(1, 51):
        flag = ""

        for i in range(0, len(encrypted)-padding_length, padding_length):
            decrypted_chunk = "".join(chr(andys_gate(ord(a), ord(b))) for a, b in zip(encrypted[i:i+padding_length], encrypted[i+padding_length:i+2*padding_length]))
            flag += decrypted_chunk

        last_chunk = "".join(chr(andys_gate(ord(a), ord(b))) for a, b in zip(encrypted[-padding_length:], "0" * padding_length))
        flag += last_chunk

        # Check if the decrypted flag is valid
        if flag.endswith("0" * (padding_length - (len(flag) % padding_length))):
            return flag

    return None

encrypted = open("encrypted", "rb").read().decode("utf-32")
decrypted_flag = decrypt(encrypted)

if decrypted_flag:
    print("Decrypted Flag:", decrypted_flag)
else:
    print("Failed to decrypt the flag.")
