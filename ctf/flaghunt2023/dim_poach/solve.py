hex_data = """
45 47 47 41 00 01 f6 ab d4 b4 00 00 00 00 22 82
e2 08 e3 90 85 0a 00 00 00 00 50 03 00 00 00 00
00 00 ac 91 85 0a 00 06 00 65 67 67 2e 70 79 0b
95 86 2c 00 09 00 80 ef eb f6 16 f2 d9 01 00 22
82 e2 08 13 0c b5 02 01 04 50 03 00 00 8f 01 00
00 42 48 03 8f 22 82 e2 08 75 91 4d 4b c3 40 10
86 ef 42 ff c3 98 4b 12 aa 01 45 3c 14 7b 92 b6
37 4f 05 11 11 d9 36 93 64 31 ee c6 d9 59 6d fe
bd fb 91 68 ea 47 16 92 25 ef be cf cc bc 2b 5f
3b 4d 0c 3b 61 f0 fa 6a 76 e2 57 89 15 a0 da 53
df f1 73 d5 8a 3a f3 af 7c 31 3b 01 f7 10 be 23
19 2c 83 02 4b f0 9f c7 c5 e2 fc e2 29 ea ce a8
cb 6f 39 72 8b dd f5 55 14 b2 23 7f 31 fc cc f3
a2 c4 b8 fb a2 f8 f2 df 9c 24 89 42 a5 09 f6 8d
20 90 ea a8 d4 d0 dd 1f de f9 d2 19 28 d3 54 66
de 98 c3 cd 0d 5c e6 00 7e d2 38 10 5b 0a b0 89
cb 8b 4c fd 40 fd 90 dc 80 ee 50 65 69 e8 9a 0f
9c 9e 41 4a 69 0e c2 40 25 5b 9c 94 1f 73 71 7f
0b 42 51 66 79 61 98 64 e7 47 c3 c3 1e 3b 86 b5
d3 ee 34 af b5 55 e5 8a 48 d3 60 ef 48 2a ce 92
b1 06 28 cd 6e 60 77 a8 48 86 5c 26 69 38 da cf
90 7e 5f 9a 3f 36 50 ef b1 dd eb 57 04 d6 c0 0d
c2 6a b3 f1 41 b6 2d aa 1a 4f 3d df af 8f c6 b5
06 5b b2 e3 44 b5 45 63 1c 5a aa ce 3a c8 4a 31
12 f4 da d2 a0 b8 5c 21 7d b3 92 53 0f c6 83 e4
7c 01 91 e6 ed b2 1a 09 ae 69 7f 2c 99 24 35 34
b6 6d 84 7a 31 e1 66 bb 56 f4 52 d5 a1 9d f1 d4
ce 85 f8 f2 17 ef 78 fc df dc 5b ad 6a 12 6c 5b
c1 52 2b 73 0a 0f da c6 38 43 00 c1 04 09 cc c3
ee bf 82 d8 9a e9 e5 8e 59 92 63 c7 4e 0a 97 56
0f a2 16 52 85 b6 3f 01 e3 90 85 0a 01 00 00 00
51 00 00 00 00 00 00 00 ac 91 85 0a 00 07 00 65
6e 63 2e 74 78 74 0b 95 86 2c 00 09 00 80 21 08
60 b6 f0 d9 01 00 22 82 e2 08 13 0c b5 02 01 04
51 00 00 00 47 00 00 00 b1 2c ec ce 22 82 e2 08
1d ca a1 16 80 30 0c 43 51 cf 57 4f 4c 4c 20 26
2a 2a 10 15 88 4a 04 02 df 26 fb 2d 0a 27 e2 3e
11 2a 84 13 df 34 ce 68 79 c7 9e 4e 2f 7b 3e d4
b2 d1 20 b0 e5 d0 f4 5f 59 c6 9e 8a 11 07 46 4a
fd ab 79 55 cf ed 05 22 82 e2 08
"""

# Remove whitespace and newlines
hex_data = hex_data.replace(" ", "").replace("\n", "")

# Convert hex to bytes
binary_data = bytes.fromhex(hex_data)

# Write the binary data to a file
with open('output.bin', 'wb') as f:
    f.write(binary_data)
