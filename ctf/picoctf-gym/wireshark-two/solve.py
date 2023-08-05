# Extraction Command
# tshark -Y "frame contains \"picoCTF\"" -r shark2.pcapng -T fields -e frame.number -e frame.time -e frame.len -e frame.protocols -e text > extracted.txt

flag_candidates = []

with open("extracted.txt", "r") as file:
    for line in file:
        start_index = line.find("picoCTF{")
        if start_index != -1:
            end_index = line.find("}", start_index)
            if end_index != -1:
                flag_text = line[start_index + 8: end_index]
                flag_candidates.append(flag_text)

converted_flags = []

for candidate in flag_candidates:
    # print(candidate)
    # hex_bytes = bytes.fromhex(candidate)
    ascii_string = ''.join([chr(int(candidate[i:i+2], 16)) for i in range(0, len(candidate), 2)])  
    print(ascii_string)

# Print the list of converted ASCII texts
# print(converted_flags)
