# Run
# python3 -c "print('a'*49968); print('a'*32)" | nc mercury.picoctf.net 36981

# Used in the previous command
P = 'a'*32

# Paste
C_HEX = '0346483f243d1959563d1907563d1903543d190551023d1959073d1902573d19'

# Encrypted flag
ENC_FLAG_HEX = '5541103a246e415e036c4c5f0e3d415a513e4a560050644859536b4f57003d4c'

if __name__ == '__main__':

    p = P.encode('ascii')
    c = bytes.fromhex(C_HEX)

    key = bytearray()
    for i, j in zip(p, c):
        key.append(i ^ j)

    enc_flag = bytes.fromhex(ENC_FLAG_HEX)

    flag = bytearray()
    for i, j in zip(enc_flag, key):
        flag.append(i ^ j)

    print(flag.decode('ascii'))
