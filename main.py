"""
S-AES CBC Mode — Full Demonstration

This script demonstrates:
1. Creating and encrypting a text file with S-AES in CBC mode
2. Creating and encrypting a BMP image to show binary data support
3. Running a brute force attack to recover the key
4. Decrypting the files using the recovered key

Authors: Ihab Haydaw (59027), Anthony Sfeir (60622)
"""

import os
import struct
import time
from cbc_mode import encrypt_file, decrypt_file, encrypt_cbc, decrypt_cbc
from brute_force import brute_force_attack


def create_sample_file(filename="sample.txt"):
    """Creates a sample text file to be used for encryption."""
    content = (
        b"Dear Students,\n\n"
        b"This is a sample plaintext file used to demonstrate S-AES in CBC mode.\n"
        b"The goal is to encrypt this file, and then successfully decrypt it "
        b"using a Brute Force attack.\n"
        b"Cryptography is fascinating!\n\n"
        b"Best Regards,\n"
        b"The Team."
    )
    with open(filename, "wb") as f:
        f.write(content)
    print(f"  [+] Created sample file '{filename}' with {len(content)} bytes.")
    return content


def create_sample_bmp(filename="sample.bmp", width=16, height=16):
    """
    Creates a small BMP image programmatically (no external libraries).
    Generates a 16x16 pixel gradient pattern.
    Returns the raw bytes of the file.
    """
    # BMP Header (14 bytes)
    row_size = (width * 3 + 3) & ~3  # rows padded to 4-byte boundary
    pixel_data_size = row_size * height
    file_size = 54 + pixel_data_size  # 14 (file header) + 40 (info header) + pixels

    bmp = bytearray()

    # File Header (14 bytes)
    bmp += b'BM'                            # Signature
    bmp += struct.pack('<I', file_size)      # File size
    bmp += struct.pack('<HH', 0, 0)         # Reserved
    bmp += struct.pack('<I', 54)            # Pixel data offset

    # Info Header (40 bytes) — BITMAPINFOHEADER
    bmp += struct.pack('<I', 40)            # Header size
    bmp += struct.pack('<i', width)         # Width
    bmp += struct.pack('<i', height)        # Height
    bmp += struct.pack('<H', 1)             # Color planes
    bmp += struct.pack('<H', 24)            # Bits per pixel (24-bit RGB)
    bmp += struct.pack('<I', 0)             # Compression (none)
    bmp += struct.pack('<I', pixel_data_size)  # Image size
    bmp += struct.pack('<i', 2835)          # Horizontal resolution (72 DPI)
    bmp += struct.pack('<i', 2835)          # Vertical resolution (72 DPI)
    bmp += struct.pack('<I', 0)             # Colors in palette
    bmp += struct.pack('<I', 0)             # Important colors

    # Pixel Data (bottom-up, BGR format)
    for y in range(height):
        for x in range(width):
            r = int((x / width) * 255)
            g = int((y / height) * 255)
            b = 128
            bmp += struct.pack('BBB', b, g, r)  # BGR order
        # Pad row to 4-byte boundary
        padding = row_size - width * 3
        bmp += b'\x00' * padding

    with open(filename, 'wb') as f:
        f.write(bmp)

    print(f"  [+] Created sample BMP image '{filename}' "
          f"({width}x{height}, {len(bmp)} bytes)")
    return bytes(bmp)


def main():
    print("=" * 60)
    print("   S-AES CBC MODE — FULL DEMONSTRATION")
    print("=" * 60)

    # =========================================================================
    # PART 1: Text File Encryption/Decryption
    # =========================================================================
    print("\n" + "-" * 60)
    print("  PART 1: TEXT FILE ENCRYPTION")
    print("-" * 60)

    pt_file = "sample.txt"
    ct_file = "sample.enc"
    dec_file = "sample_decrypted.txt"

    content = create_sample_file(pt_file)

    # Define secret Key and IV
    secret_key = 0x1337
    iv = 0xAAAA

    print(f"\n  [1] Encrypting '{pt_file}' -> '{ct_file}'")
    print(f"      Key: 0x{secret_key:04X}, IV: 0x{iv:04X}")
    encrypt_file(pt_file, ct_file, secret_key, iv)
    ct_size = os.path.getsize(ct_file)
    print(f"      Encryption successful ({ct_size} bytes)")

    # Show a snippet of the ciphertext
    with open(ct_file, "rb") as f:
        ct_preview = f.read(20)
    print(f"      Ciphertext preview: {ct_preview.hex()}")

    # Decrypt to verify
    print(f"\n  [2] Decrypting '{ct_file}' -> '{dec_file}'")
    decrypt_file(ct_file, dec_file, secret_key, iv)

    with open(pt_file, "rb") as f1, open(dec_file, "rb") as f2:
        if f1.read() == f2.read():
            print("      [OK] Decrypted file matches original!")
        else:
            print("      [ERROR] Mismatch!")

    # =========================================================================
    # PART 2: Image (BMP) Encryption/Decryption
    # =========================================================================
    print("\n" + "-" * 60)
    print("  PART 2: IMAGE (BMP) ENCRYPTION")
    print("-" * 60)

    bmp_file = "sample.bmp"
    bmp_enc_file = "sample.bmp.enc"
    bmp_dec_file = "sample_decrypted.bmp"

    bmp_data = create_sample_bmp(bmp_file)

    img_key = 0x7E3F
    img_iv = 0x5555

    print(f"\n  [1] Encrypting '{bmp_file}' -> '{bmp_enc_file}'")
    print(f"      Key: 0x{img_key:04X}, IV: 0x{img_iv:04X}")
    encrypt_file(bmp_file, bmp_enc_file, img_key, img_iv)
    enc_size = os.path.getsize(bmp_enc_file)
    print(f"      Encryption successful ({enc_size} bytes)")

    print(f"\n  [2] Decrypting '{bmp_enc_file}' -> '{bmp_dec_file}'")
    decrypt_file(bmp_enc_file, bmp_dec_file, img_key, img_iv)

    with open(bmp_file, "rb") as f1, open(bmp_dec_file, "rb") as f2:
        if f1.read() == f2.read():
            print("      [OK] Decrypted image matches original!")
        else:
            print("      [ERROR] Image mismatch!")

    # =========================================================================
    # PART 3: Brute Force Attack on Text File
    # =========================================================================
    print("\n" + "-" * 60)
    print("  PART 3: BRUTE FORCE ATTACK ON TEXT CIPHERTEXT")
    print("-" * 60)

    print("\n  Attacker scenario:")
    print("  - Intercepted the encrypted file 'sample.enc'")
    print(f"  - Knows the IV is 0x{iv:04X}")
    print("  - Knows the file starts with 'Dear Students,'")

    with open(ct_file, "rb") as f:
        intercepted_ct = f.read()

    known_header = b"Dear Students,"
    print(f"\n  Running brute force attack on {len(intercepted_ct)} bytes...")
    found_key = brute_force_attack(intercepted_ct, iv, known_header)

    if found_key is not None:
        print(f"\n  [3] Decrypting with recovered key 0x{found_key:04X}...")
        bf_dec_file = "sample_bruteforced.txt"
        decrypt_file(ct_file, bf_dec_file, found_key, iv)

        with open(pt_file, "rb") as f1, open(bf_dec_file, "rb") as f2:
            if f1.read() == f2.read():
                print(f"      [SUCCESS] Brute-forced decryption matches original!")
            else:
                print(f"      [ERROR] Mismatch after brute force decryption")

    # =========================================================================
    # PART 4: Brute Force Attack on Image
    # =========================================================================
    print("\n" + "-" * 60)
    print("  PART 4: BRUTE FORCE ATTACK ON IMAGE CIPHERTEXT")
    print("-" * 60)

    print("\n  Attacker scenario:")
    print("  - Intercepted the encrypted BMP file")
    print(f"  - Knows the IV is 0x{img_iv:04X}")
    print("  - Knows all BMP files start with the signature 'BM'")

    with open(bmp_enc_file, "rb") as f:
        intercepted_bmp_ct = f.read()

    bmp_header = b"BM"
    print(f"\n  Running brute force attack on {len(intercepted_bmp_ct)} bytes...")
    found_img_key = brute_force_attack(intercepted_bmp_ct, img_iv, bmp_header)

    if found_img_key is not None:
        print(f"\n  Decrypting image with recovered key 0x{found_img_key:04X}...")
        bf_bmp_dec = "sample_bruteforced.bmp"
        decrypt_file(bmp_enc_file, bf_bmp_dec, found_img_key, img_iv)

        with open(bmp_file, "rb") as f1, open(bf_bmp_dec, "rb") as f2:
            if f1.read() == f2.read():
                print(f"      [SUCCESS] Brute-forced image decryption matches original!")
            else:
                print(f"      [ERROR] Image mismatch after brute force")

    # =========================================================================
    # SUMMARY
    # =========================================================================
    print("\n" + "=" * 60)
    print("   DEMONSTRATION COMPLETE")
    print("=" * 60)
    print(f"  Text encryption key:   0x{secret_key:04X}  |  Found: 0x{found_key:04X}"
          if found_key else "")
    print(f"  Image encryption key:  0x{img_key:04X}  |  Found: 0x{found_img_key:04X}"
          if found_img_key else "")
    print(f"  Key space:  2^16 = 65,536 keys")
    print(f"  Conclusion: S-AES is educational but trivially breakable!")
    print("=" * 60)


if __name__ == "__main__":
    main()
