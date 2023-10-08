# Read the content of the file
with open("thespace.txt", "r") as file:
    file_content = file.read()

# Split the content using the "$!" delimiter
split_strings = file_content.split("$!")

# Count the occurrences of each splitted string
string_counts = {}
for string in split_strings:
    string = string.strip()  # Remove leading/trailing whitespace
    if string:
        if string in string_counts:
            string_counts[string] += 1
        else:
            string_counts[string] = 1

# Sort the counts in descending order
sorted_counts = sorted(string_counts.items(), key=lambda x: x[1], reverse=True)

# Print the sorted counts and corresponding strings
for string, count in sorted_counts:
    print(f"{string}: {count}")
