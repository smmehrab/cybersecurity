#include <iostream>
#include <string>
#include <vector>

using namespace std;

void undoMagic(const std::string& encoded_text, int monkey) {
    vector<std::vector<char>> spell(monkey, vector<char>(encoded_text.size(), ' '));
    int magician_number = 1;
    int abraka = 0, dabra = 0;

    for (char c : encoded_text) {
        spell[abraka][dabra] = c;
        if (abraka == 0) {
            magician_number = 1;
        } else if (abraka == monkey - 1) {
            magician_number = -1;
        }
        abraka += magician_number;
        dabra += 1;
    }

    string original_text;
    for (const auto& row : spell) {
        for (char c : row) {
            if (c != ' ') {
                original_text += c;
            }
        }
    }
    cout<< original_text << endl;

    undoMagic(original_text, 5);
}

int main() {
    string encoded_text = "C_1_}_ShSy0lga{S3t7ea1R";  // Replace with the encoded text
    int monkey = 5;

    undoMagic(encoded_text, monkey);

    //std::cout << "Encoded Text: " << encoded_text << std::endl;
    //std::cout << original_text << std::endl;


    return 0;
}