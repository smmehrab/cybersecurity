import random

def main():
    random.seed(0x2023)

    encrypted_flag = ['46', '249', '22', '52', '72', '35', '21', '72', '222', '17', '248', '41', '72', '98', '60', '3', '218', '120', '179', '248', '93', '98', '133', '100', '112', '125', '246', '252', '196', '138', '134', '123', '164', '158']
    encrypted_flag = [int(ch) for ch in encrypted_flag]
    n = len(encrypted_flag)

    encrypted_flag.reverse()

    flag = []
    for code in encrypted_flag:
        flag.append(chr(code ^ int.from_bytes(random.randbytes(1), byteorder="big")))

    print("".join(flag))


if __name__ == "__main__":
    main()