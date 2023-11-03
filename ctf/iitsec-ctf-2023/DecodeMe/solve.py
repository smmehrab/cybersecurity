def undoMagic(encoded_text):
    charsList = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"

    result = ""
    i = 0
    while i < len(encoded_text):
        chunk = encoded_text[i:i + 5]
        chunk_value = 0
        for char in chunk:
            chunk_value = chunk_value * 85 + charsList.index(char)

        decoded_chars = []
        for _ in range(4):
            decoded_chars.append(chr(chunk_value % 256))
            chunk_value //= 256

        result += ''.join(reversed(decoded_chars))
        i += 5

    return result

if __name__ == "__main__":
    encoded_text = "Lo<6{X>?OxWnoi!Us5q=Xg6Pd"  # Replace with the actual encoded text

    decoded_text = undoMagic(encoded_text)

    print("Encoded Text:", encoded_text)
    print("Decoded Text:", decoded_text)