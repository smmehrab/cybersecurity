import base64
import zlib
import qrcode

BLOCK_FULL  = chr(9608)
BLOCK_UPPER = chr(9600)
BLOCK_LOWER = chr(9604)
BLOCK_EMPTY = chr(160)

# Provided shard data
shards = [
    "eJw7tOAQGD6a1nBoAfEQrJyLFB2oEK/WR9Na8EpyIdgNUHejOR+HCVBVWC0nEABwEyn1NNEBDbcR3dUIX+N1PZoQie5G0U27iMYbFrSylgitJGYHKlgLANMzZpM=",
    "eJx7NK3h0AJ0+GhaC6YgQhKugwuLGD6NKKZyEdaBZDipmnG4CCyMUzMR3sChF+w8PNqhUnidjdPJLSQGGNw4pEDjItqHhAOMJENIdDVBrajeQgsiAroJOpyCsKaKjwFzVGmR",
    "eJw7tOAQyfDRtAYQxUWOzhYgAmuGGoIiR6wxZNiMVysOqzGcSG17ydSK4S48judC8PEELw4TsTgayRgwE4+xJHoZxQ1E6cXnaiLCCM3pYB1AAkcKwTAOqw2U+BkAxyVnzw==",
    "eJw7tOAQCnw0rQWNAWUi8RGQ69G0BkxR4iAXuRqJ1IrDaVj0EuUJsCKCFmMNJSwWI1mJx3Yk07gwZPBYRVZ4UVUr2HHYfYzTv2AJ3F6mkqvR0zVFXsbwCwVuBgDIM2dF",
    "eJw7tOAQmZCLWIWPpjXAGC0omuESNLKYgFag9UguwutyFN0ENKEb0YLT1SjG4w0MLgzj8DoUq2aSnI01wIi2kYBeIq0lK3kAfUkV/yIlWqyuAJuOYsWjaR0ofsbrfCRJJCYAhrBpBw==",
    "eJw7tOAQHD6a1nJoAfGQixTF1NP6aFoDblm8kkj2YniVoN+BJpPkajQDCeqFqsfqDmI14/UySuDg1ACUgCCi7cYNuZAsJRAxWBRw4ZQhwgjcEU2kswnbhdVc/KkTPwQApZ9n3w==",
    "eJw7tODQgkfTGg4hKGwQhxQXLvW4IdwkAnofTWvBLUnQXgzdQGsRNuM1m4BxXChmkmYMFxE6UJSgcLA5GywEJNB0YfUeMbbjdAvCcrAgiUaRkU6waIVbimQ77uCi3Gas4Uhk2qHAXgCiVWvx",
    "eJw7tOAQAfhoWgN24RYuQlrxGIlFLxaLcNjNhUeOECTb0Vi1YjgCp6uoay/VtT6a1gGMUVraCzUexRYMK6ECuLUPTGgRYTkXqvoG4myEKgQAFfFk5Q==",
    "eJw7tOAQmZALQj2a1oJEgRgNSDxkCJZBYnBhVUWi5Q2YthA0lAuny4i2GItN6AEBNxbFdFyeJiosuFB1EO1oqF5sDibCFLA6FH+TZDGW8CYWAm3GHdFE2AuPEnI0k+toirQCAJFdaj8=",
    "eJw7tOAQCnw0rQFCtRxaQAhyoaiE6sSEOCS4cKnGaTPQILhZOHQTA+FasTqMgM+pai/OICPCxwT14nQ1STqx+PjRtA4S9eKwERjUSDJYjKWas8Fm409ZNAwwEkwAABIKajM=",
    "eJx7NK3l0ALS4KNpDRAGFzFqcRhPhF4ku+BWkqSZAnvRXA+1nwx7SQksAm7GGZZ4nc6FoQ0eph3EaKfY2WRpBboRLc7xe7YBXTdeBVgkkVRgcTdcFotB0KAiLqIJeAoAuxtplQ==",
    "eJw7tOAQDvhoWgeIaEEXbUBwuHDpRdfTginIhZBtIM4Yku3F5pIGsvXitBaPB5CkuJBFsYQHXiOID2gsjuHCUESxl3Faj1cvCTFNciyBvd6CVzNRHuci4Ei80hSkLQB1QWYV",
    "eJw7tOAQED6a1oBEIeCjaS2oAqiSDVxQBUAmXqVo2mBMLuLUYzWYC1VNAxoHQxea37iwihIHiXA2ztDAqZeQg6GayXIw3GKiI4lkD+PwDpDC0IzkCDiT9PAadD6mglYAmBRpDw==",
    "eJw7tOAQVvhoWgM2wRZkLhd2rVCVWE1AkudCsQjNaKz2obgOj+UEfUK0XkxIlFYc7ibRWhRTiNCLM8DJ10tKOGMxiiK9OCMfKWRI8zJcNVQ/ThtwuBuLemwuIeBrvPkCAHVgajc=",
    "eJw7tOAQmZCLXI1kan00rQGnXqgcGfY+mtZClCFAdVxo6snyMVQ/0C4STCIivHCaRv1oIsrhZFoLNpsLQ4QEX+N0dAMOIRQZ4qzGkVK4CMjjgwAbpGYV",
    "eJw7tOAQmZCLXI1oWh9Na6DI2kfTWvCpRzGeC6wci41ohuBwE3Z3E3AAmmYSvYvD02guhzoBajaGFVi0E+0MgtGMFA4YRnKR5VsiLSZCKxnWE+NfnMZSEscA/3dnLQ==",
]

def text_to_atoms(text):
    lines = text.split('\n')
    size = len(lines)
    buf = [False] * size**2

    for y in range(0, size, 2):
        line = lines[y]
        for x in range(size):
            a = line[x * 2] == BLOCK_FULL or line[x * 2] == BLOCK_UPPER
            b = line[x * 2] == BLOCK_FULL or line[x * 2] == BLOCK_LOWER
            buf[y * size + x] = a
            if y + 1 < size:
                buf[(y + 1) * size + x] = b

    atoms = []
    for y in range(size):
        for x in range(size):
            atoms.append((x, y, buf[y * size + x]))

    return atoms, size

def reverse_code_atoms(atoms, size):
    code = qrcode.QRCode(
        border=0,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
    )
    for atom in atoms:
        x, y, is_set = atom
        code.modules[y][x] = is_set

    return code

def reverse_soul_code(code):
    return code.get_matrix()

# Function to decode the shard data
def decode_shard(shard):
    compressed_data = base64.b64decode(shard)
    uncompressed_data = zlib.decompress(compressed_data)
    return uncompressed_data

# Function to reconstruct the QR code
def reconstruct_qr_code(shards):
    size = None
    atoms = []
    for shard in shards:
        shard_data = decode_shard(shard).decode('utf-8')
        lines = shard_data.split('\n')
        for y, line in enumerate(lines):
            for x, char in enumerate(line):
                if char == BLOCK_FULL:
                    is_set = True
                else:
                    is_set = False
                atoms.append((x, y, is_set))
        size = len(lines)
    code = qrcode.QRCode(
        border=0,
        error_correction=qrcode.constants.ERROR_CORRECT_H
    )
    code.modules = [[False for _ in range(size)] for _ in range(size)]
    for x, y, is_set in atoms:
        code.modules[y][x] = is_set
    return code

# Function to extract the soul from the reconstructed QR code
def extract_soul(qr_code):
    qr_data = qr_code.make_image(fill_color="black", back_color="white")
    qr_data.save("reconstructed_qr.png")  # Save the reconstructed QR code as an image
    soul = qr_code.make_image(fill_color="black", back_color="white").get_image()
    return soul

# Reconstruct the QR code from the provided shards
reconstructed_qr_code = reconstruct_qr_code(shards)

# Extract the soul from the reconstructed QR code
recovered_soul = extract_soul(reconstructed_qr_code)

print("Soul recovered:")
print(recovered_soul)
