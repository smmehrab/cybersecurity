data = [67, 51, 123, 101, 97, 83, 121, 95, 82, 101, 118, 51, 114, 115, 51, 125]

flag = ""
for i in range(len(data)):
    flag += chr(data[i])

print(flag)