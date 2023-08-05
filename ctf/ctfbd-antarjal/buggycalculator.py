#!/usr/bin/python3
import ctypes

cheat = 0

def check_input(input):
    banned = ['.', '+', '_', ' ', '`','"',',']
    banned_words = ["class","cheat","os","system","builtin","eval","exec","flag","global"]
    for word in banned_words:
        if word in input:
            return False
    for ch in input:
        if ch in banned:
            return False
    return True

def flag():
    global cheat
    if cheat == 1337:
        print("CTFBD{REDACTED}")
    else:
        print(cheat)
        print("You are cheating. Go Away")

def main():
    print("Input the expression Ex. print(5-1)")
    expression = input('> ').lower()
    check = check_input(expression)
    if check:
        exec(expression, {'local': globals(), '__builtins__': {}, 'print':print})
    else:
        print(f"Bad Charecter or Word Detected!")

     
    # # Define the function pointer type that matches the signature of the 'flag' function
    # # Replace '<return_type>' with the appropriate return type
    # FuncType = ctypes.CFUNCTYPE(ctypes.c_int)

    # # Create a function pointer instance with the correct memory address
    # # Replace '0x7f5d86598540' with the actual memory address of the 'flag' function
    # function_pointer = FuncType(0x7f5d86598540)

    # # Call the function using the function pointer
    # function_pointer()

if __name__ == "__main__":
    main()