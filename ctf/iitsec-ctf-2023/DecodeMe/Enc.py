def doingMagic(text):
    charsList = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"

    result = ""
    i = 0
    while i < len(text):
        chunk = text[i:i+4]
        chunk_value = 0
        for char in chunk:
            chunk_value = chunk_value * 256 + ord(char)
        
        encoded_chars = []
        for _ in range(5):
            encoded_chars.append(charsList[chunk_value % 85])
            chunk_value //= 85
        
        result += ''.join(reversed(encoded_chars))
        i += 4
    
    return result

if __name__ == "__main__":
    flag = "C3{i_am_not_the_flag}"
    
    encoded_text = doingMagic(flag)

    print("Original Text:", flag)
    print("Encoded Text:", encoded_text)
