def doingMagic(text, monkey):
    spell = [[' ' for _ in range(len(text))] for _ in range(monkey)]
    magician_number = 1 
    abraka, dabra = 0, 0

    for char in text:
        spell[abraka][dabra] = char
        if abraka == 0:
            magician_number = 1
        elif abraka == monkey - 1:
            magician_number = -1
        abraka += magician_number
        dabra += 1

    magic_spell = ''.join(char for abraka in spell for char in abraka if char != ' ')
    return magic_spell

if __name__ == "__main__":
    plaintext = "C3{I_AM_NOT_the_FLAG}"
    monkey = 5

    magic_spell = doingMagic(plaintext, monkey)

    print("Original Text:", plaintext)
    print("Magic Spell:", magic_spell)
