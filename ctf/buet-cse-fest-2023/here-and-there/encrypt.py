import json

def main():

    keys = json.loads(open("keys.json", "r").read())
    flag = open("flag.txt", "r").read().strip()
    galf = []

    for each in list(flag):
        galf.append(pow(ord(each), keys["B"], keys["A"]))

    open("galf1.txt", "w").write(str(galf))

if __name__ == "__main__":
    main()