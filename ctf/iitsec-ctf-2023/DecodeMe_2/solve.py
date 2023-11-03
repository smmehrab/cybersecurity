def undoMagic(magic_spell, monkey):
    spell = [[' ' for _ in range(len(magic_spell))] for _ in range(monkey)]
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

    # Reconstruct the original text by reading the spell row by row
    original_text = ''.join(char for abraka in spell for char in abraka if char != ' ')

    return original_text

if __name__ == "__main":
    magic_spell = "Cl_3aSyR{_0S1}1S_ag7teh"

    monkey = 5

    original_text = undoMagic(magic_spell, monkey)

    print("Magic Spell:", magic_spell)
    print("Original Text:", original_text)