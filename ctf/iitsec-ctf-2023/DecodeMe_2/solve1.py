def undoMagic(magic_spell, monkey):
    spell_length = len(magic_spell)
    spell = [[' ' for _ in range(spell_length)] for _ in range(monkey)]
    magician_number = 1
    abraka, dabra = 0, 0

    for char in magic_spell:
        spell[abraka][dabra] = char
        if abraka == 0:
            magician_number = 1
        elif abraka == monkey - 1:
            magician_number = -1
        abraka += magician_number
        dabra += 1

    plaintext = ''.join(char for abraka in spell for char in abraka)

    return plaintext

if __name__ == "__main__":
    magic_spell = "Cl_3aSyR{_0S1}1S_ag7teh"

    monkey = 5

    plaintext = undoMagic(magic_spell, monkey)

    print("Magic Spell:", magic_spell)
    print("Original Text:", plaintext)
