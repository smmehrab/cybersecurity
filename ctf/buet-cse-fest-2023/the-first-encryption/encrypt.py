import random

def main():
    random.seed(0x2023)

    flag = open("flag.txt", "r").read().strip()
    flag_len = len(flag)

    encrypted_flag = []
    for ch in list(flag):
        encrypted_flag.append(str(ord(ch) ^ int.from_bytes(random.randbytes(1), byteorder="big")))

    encrypted_flag.reverse()
    open("galf.txt", "w").write(str(encrypted_flag))


if __name__ == "__main__":
    main()