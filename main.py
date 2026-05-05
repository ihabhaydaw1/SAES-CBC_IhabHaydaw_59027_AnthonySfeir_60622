import os
import time
from cbc_mode import encrypt_file, decrypt_file
from brute_force import brute_force_attack

def create_sample_file(filename="sample.txt"):
    """Creates a sample file to be used for encryption."""
    content = b"Dear Students,\n\nThis is a sample plaintext file used to demonstrate S-AES in CBC mode.\n" \
              b"The goal is to encrypt this file, and then successfully decrypt it using a Brute Force attack.\n" \
              b"Cryptography is fascinating!\n" \
              b"Best Regards,\nThe Team."
    with open(filename, "wb") as f:
        f.write(content)
    print(f"[+] Created sample file '{filename}' with {len(content)} bytes.")

def main():
    print("="*50)
    print(" S-AES CBC Mode & Brute Force Demonstration ")
    print("="*50)
    
    # 1. Create a sample file
    pt_file = "sample.txt"
    ct_file = "sample.enc"
    dec_file = "sample_decrypted.txt"
    
    create_sample_file(pt_file)
    
    # Define our secret Key and IV
    secret_key = 0x1337
    iv = 0xAAAA
    
    print(f"\n[1] Encrypting '{pt_file}' to '{ct_file}'...")
    print(f"    Secret Key: 0x{secret_key:04X}, IV: 0x{iv:04X}")
    encrypt_file(pt_file, ct_file, secret_key, iv)
    print("    Encryption successful.")
    
    # 2. Simulate the attacker intercepting the ciphertext
    print("\n[2] Attacker intercepts the ciphertext...")
    with open(ct_file, "rb") as f:
        intercepted_ct = f.read()
    
    print(f"    Intercepted {len(intercepted_ct)} bytes of ciphertext.")
    print("    Attacker knows the IV is 0xAAAA and the file starts with 'Dear Students,'.")
    
    # 3. Attacker runs brute force
    print("\n[3] Running Brute Force Attack...")
    known_header = b"Dear Students,"
    found_key = brute_force_attack(intercepted_ct, iv, known_header)
    
    # 4. Decrypt with the found key
    if found_key is not None:
        print(f"\n[4] Decrypting the file using the found key 0x{found_key:04X}...")
        decrypt_file(ct_file, dec_file, found_key, iv)
        print(f"    Decrypted data saved to '{dec_file}'.")
        
        # Verify
        with open(pt_file, "rb") as f1, open(dec_file, "rb") as f2:
            if f1.read() == f2.read():
                print("\n[SUCCESS] The decrypted file matches the original plaintext perfectly!")
            else:
                print("\n[ERROR] The decrypted file does not match the original plaintext.")
    else:
        print("\n[ERROR] Brute force attack failed to find the key.")

if __name__ == "__main__":
    main()
