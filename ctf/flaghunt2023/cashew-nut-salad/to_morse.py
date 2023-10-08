# Open the input file in read mode
with open("input.txt", "r") as input_file:
    # Read the lines from the input file
    lines = input_file.readlines()

# Define the conversion dictionary
conversion_dict = {"dot": ".", "dash": "-"}

# Open the output file in write mode
with open("converted.txt", "w") as output_file:
    # Iterate over each line in the input
    for line in lines:
        # Replace 'dot' and 'dash' in the line according to the conversion dictionary
        converted_line = line
        for key, value in conversion_dict.items():
            converted_line = converted_line.replace(key, value)
        # Write the converted line to the output file
        output_file.write(converted_line[:-1] + " ")