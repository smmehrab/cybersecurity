from collections import defaultdict

# Function to read the file and count line frequencies
def count_line_frequencies(file_path):
    line_frequencies = defaultdict(int)

    try:
        with open(file_path, 'r') as file:
            for line in file:
                # Remove leading and trailing whitespace and convert to lowercase (if needed)
                cleaned_line = line.strip().lower()  # You can remove .lower() if case sensitivity is desired
                line_frequencies[cleaned_line] += 1

    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
        return None

    return line_frequencies

# Function to print frequencies in descending order
def print_frequencies_descending(line_frequencies):
    sorted_frequencies = sorted(line_frequencies.items(), key=lambda x: x[1], reverse=True)

    print("Line Frequencies in Descending Order:")
    for line, frequency in sorted_frequencies:
        print(f"{line}: {frequency}")

# Main program
if __name__ == "__main__":
    file_path = input("Enter the path to the file: ")
    frequencies = count_line_frequencies(file_path)

    if frequencies:
        print_frequencies_descending(frequencies)
