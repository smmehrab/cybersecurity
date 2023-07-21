import re

with open("regex.txt", "r") as file:
    text = file.read()

unique_sequence = None
pattern = r"{([a-zA-Z0-9_]{1,21})}"

matches = re.findall(pattern, text)

for match in matches:
    sequence = match.strip()
    if text.count(match) == 1:
        unique_sequence = sequence
        print(sequence)

if unique_sequence:
    print("Unique sequence found:", unique_sequence)
else:
    print("No unique sequence found.")
