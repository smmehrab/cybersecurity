from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
import base64
import os

def encrypt_string(plaintext, key):
    alkajhshhaggaghsh = os.urandom(16)
    kskjhsgaffsfvaffaf = AES.new(key, AES.MODE_CBC, alkajhshhaggaghsh)
    kajhshggaffsvaggsgi = pad(plaintext.encode(), AES.block_size)
    pozhavshahsghss = kskjhsgaffsfvaffaf.encrypt(kajhshggaffsvaggsgi)
    paoksbbxhhs = base64.b64encode(alkajhshhaggaghsh + pozhavshahsghss).decode()
    return paoksbbxhhs

plaintext = "hello world"
key = b'key'

encrypted_data = encrypt_string(plaintext, key)
print(encrypted_data)
