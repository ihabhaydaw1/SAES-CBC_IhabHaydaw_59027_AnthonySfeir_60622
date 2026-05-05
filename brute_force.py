import time
from cbc_mode import decrypt_cbc

def brute_force_attack(ciphertext: bytes, iv: int, known_plaintext: bytes):
    """
    Attempts to find the 16-bit key used to encrypt the ciphertext
    by checking all possible 2^16 keys.
    Returns the key if found, or None.
    """
    print(f"Starting brute force attack (Searching 65,536 keys)...")
    print(f"Looking for known plaintext: {known_plaintext}")
    
    start_time = time.time()
    
    # We only need to check the first few blocks to verify the known plaintext.
    # So we don't have to decrypt the entire file for every key.
    
    # Calculate how many bytes we actually need to verify
    # Let's align to the block size
    from cbc_mode import BLOCK_SIZE_BYTES
    needed_length = len(known_plaintext)
    # We round up to nearest multiple of BLOCK_SIZE_BYTES
    if needed_length % BLOCK_SIZE_BYTES != 0:
        needed_length += BLOCK_SIZE_BYTES - (needed_length % BLOCK_SIZE_BYTES)
        
    # Take just enough ciphertext to cover the known plaintext
    short_ciphertext = ciphertext[:needed_length]
    
    for key in range(0x10000): # 0x0000 to 0xFFFF
        try:
            # We use the internal decrypt_cbc on the short ciphertext
            # We don't unpad it here because we might truncate the padding
            # We'll just check if the known_plaintext is at the start
            
            # Re-implementing a small portion of decrypt_cbc for speed on just the required blocks:
            pt = bytearray()
            prev_block = iv
            
            for i in range(0, len(short_ciphertext), BLOCK_SIZE_BYTES):
                block = (short_ciphertext[i] << 8) | short_ciphertext[i+1]
                from saes import decrypt_block
                dec_block = decrypt_block(block, key)
                dec_block ^= prev_block
                
                pt.append((dec_block >> 8) & 0xFF)
                pt.append(dec_block & 0xFF)
                
                prev_block = block
                
            if bytes(pt).startswith(known_plaintext):
                end_time = time.time()
                print(f"[*] Key Found! Key = 0x{key:04X}")
                print(f"[*] Time taken: {end_time - start_time:.2f} seconds.")
                return key
                
        except Exception:
            # If any decryption error happens, just continue
            continue
            
    end_time = time.time()
    print(f"[-] Key not found.")
    print(f"[-] Time taken: {end_time - start_time:.2f} seconds.")
    return None

if __name__ == "__main__":
    from cbc_mode import encrypt_cbc
    # Quick test
    secret = b"CONFIDENTIAL: The password is 's3cr3t'"
    test_key = 0x4B29
    test_iv = 0x0000
    
    ct = encrypt_cbc(secret, test_key, test_iv)
    
    print("Testing Brute Force...")
    found_key = brute_force_attack(ct, test_iv, b"CONFIDENTIAL")
    
    if found_key is not None:
        print(f"Full decrypted message: {decrypt_cbc(ct, found_key, test_iv)}")
    else:
        print("Test failed.")
