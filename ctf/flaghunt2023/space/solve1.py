# Read the content of the file
with open("thespace.txt", "r") as file:
    file_content = file.read()

# Split the content using the "$!" delimiter
split_strings = file_content.split("$!")

converted_characters = []  # List to store the converted characters

# Convert each 8-bit binary string to Unicode and character
for string in split_strings:
    string = string.strip()  # Remove leading/trailing whitespace
    if string:
        try:
            unicode_code = int(string, 2)  # Convert binary string to Unicode code
            char = chr(unicode_code)       # Convert Unicode code to character
            print(f"{char}", end="")
            converted_characters.append(char)
        except ValueError:
            print(f"Invalid binary string: {string}")

# Save the converted characters to a file
with open("converted.txt", "w") as output_file:
    output_file.write("".join(converted_characters))
