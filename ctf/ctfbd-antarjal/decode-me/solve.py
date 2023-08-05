from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
import base64

def decrypt_string(ciphertext, key):
    ciphertext = base64.b64decode(ciphertext)
    alkajhshhaggaghsh = ciphertext[:16]
    pozhavshahsghss = ciphertext[16:]
    kskjhsgaffsfvaffaf = AES.new(key, AES.MODE_CBC, alkajhshhaggaghsh)
    decrypted_data = kskjhsgaffsfvaffaf.decrypt(pozhavshahsghss)
    plaintext = unpad(decrypted_data, AES.block_size).decode()
    return plaintext

encrypted_data = "acvSOR8qniQPINyK3aeln30pkM1fbLpEH15x1S+h8NZfLkt/5J8+gDyH3bnE76f0YQ8ODtci5e4fuEIEko5nzQ=="
key = b'bWTULbe1DspNhX5e4g3fqw=='

decrypted_data = decrypt_string(encrypted_data, key)
print(decrypted_data)
