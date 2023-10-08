# Define a dictionary to map Morse code to characters
morse_code_dict_reverse = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I',
    '.---': 'J', '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
    '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y', '--..': 'Z',
    '-----': '0', '.----': '1', '..---': '2', '...--': '3', '....-': '4', '.....': '5', '-....': '6',
    '--...': '7', '---..': '8', '----.': '9', ' ': ' '
}

# Function to convert Morse code to text
def morse_to_text(morse_code):
    # morse_code = morse_code.split(' ')
    # text = ''
    # for code in morse_code:
    #     if code in morse_code_dict_reverse:
    #         text += morse_code_dict_reverse[code]
    #     else:
    #         text += ' '
    # return text
    text = ''
    for c in morse_code:
        if c == "\n" or not c:
            continue
        if c not in morse_code_dict_reverse:
            return 'Invalid Morse code'
        text += morse_code_dict_reverse[c]
    return text

# Read Morse code from converted.txt
with open("new_morse.txt", "r") as morse_file:
    morse_code = morse_file.read()

# Convert Morse code to text
text = morse_to_text(morse_code)

# Write the decoded text to output.txt
with open("output.txt", "w") as output_file:
    output_file.write(text)
