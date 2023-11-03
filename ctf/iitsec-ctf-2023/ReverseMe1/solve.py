enc = "9)qh[L[hI[Ub?a[UWUAd\'=>Js"

flag = ""
for i in range(len(enc)):
    # if ord(enc[i]) > 31 and ord(enc[i]) < 127:
    flag += chr(((ord(enc[i]) - 32 +95) - 53))
print(flag)