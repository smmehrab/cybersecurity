import math

# Function to check if a number is prime
def is_prime(n):
    if n <= 1:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, int(math.sqrt(n)) + 1, 2):
        if n % i == 0:
            return False
    return True

# Iterate through possible values of the second number
for second_number in range(2, 42):
    # Calculate the corresponding first number
    first_number = (2 ** (second_number - 1)) * ((2 ** second_number) - 1)

    # Check if the first number meets the specified range
    if 20000 < first_number < 150000000000:
        # Calculate the sum of factors of the first number
        factors_sum = sum([i for i in range(1, first_number) if first_number % i == 0])

        # Check if the sum of factors is equal to the first number
        if factors_sum == first_number and is_prime(2 ** second_number - 1):
            # Print the valid pair of numbers
            print(f"First Number: {first_number}, Second Number: {second_number}")
