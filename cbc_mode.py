import os
from saes import encrypt_block, decrypt_block

BLOCK_SIZE_BYTES = 2  # 16 bits

def pad(data: bytes) -> bytes:
    """
    Applies PKCS#7-style padding for a 2-byte block size.
    If 1 byte is needed, appends 0x01.
    If 0 bytes are needed (perfectly aligned), appends 0x02 0x02.
    """
    pad_len = BLOCK_SIZE_BYTES - (len(data) % BLOCK_SIZE_BYTES)
    return data + bytes([pad_len] * pad_len)

def unpad(data: bytes) -> bytes:
    """
    Removes PKCS#7-style padding.
    """
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE_BYTES:
        raise ValueError("Invalid padding.")
    return data[:-pad_len]

def encrypt_cbc(plaintext: bytes, key: int, iv: int) -> bytes:
    """
    Encrypts plaintext using S-AES in CBC mode.
    key and iv should be 16-bit integers.
    """
    padded_data = pad(plaintext)
    ciphertext = bytearray()
    
    prev_block = iv
    
    for i in range(0, len(padded_data), BLOCK_SIZE_BYTES):
        # Extract 16-bit block
        block = (padded_data[i] << 8) | padded_data[i+1]
        
        # CBC Mode: XOR with previous ciphertext block (or IV)
        block ^= prev_block
        
        # Encrypt the block
        enc_block = encrypt_block(block, key)
        
        # Append to ciphertext
        ciphertext.append((enc_block >> 8) & 0xFF)
        ciphertext.append(enc_block & 0xFF)
        
        prev_block = enc_block
        
    return bytes(ciphertext)

def decrypt_cbc(ciphertext: bytes, key: int, iv: int) -> bytes:
    """
    Decrypts ciphertext using S-AES in CBC mode.
    """
    if len(ciphertext) % BLOCK_SIZE_BYTES != 0:
        raise ValueError("Ciphertext length must be a multiple of the block size.")
        
    plaintext = bytearray()
    prev_block = iv
    
    for i in range(0, len(ciphertext), BLOCK_SIZE_BYTES):
        # Extract 16-bit block
        block = (ciphertext[i] << 8) | ciphertext[i+1]
        
        # Decrypt the block
        dec_block = decrypt_block(block, key)
        
        # CBC Mode: XOR with previous ciphertext block (or IV)
        dec_block ^= prev_block
        
        # Append to plaintext
        plaintext.append((dec_block >> 8) & 0xFF)
        plaintext.append(dec_block & 0xFF)
        
        prev_block = block
        
    return unpad(bytes(plaintext))

def encrypt_file(input_path: str, output_path: str, key: int, iv: int):
    """Encrypts a file and saves the output."""
    with open(input_path, 'rb') as f:
        data = f.read()
    
    ciphertext = encrypt_cbc(data, key, iv)
    
    with open(output_path, 'wb') as f:
        f.write(ciphertext)

def decrypt_file(input_path: str, output_path: str, key: int, iv: int):
    """Decrypts a file and saves the output."""
    with open(input_path, 'rb') as f:
        data = f.read()
        
    plaintext = decrypt_cbc(data, key, iv)
    
    with open(output_path, 'wb') as f:
        f.write(plaintext)

if __name__ == "__main__":
    # Simple test
    test_key = 0x8A21
    test_iv = 0x1111
    message = b"Hello S-AES CBC Mode!"
    
    ct = encrypt_cbc(message, test_key, test_iv)
    pt = decrypt_cbc(ct, test_key, test_iv)
    
    print(f"Original:   {message}")
    print(f"Ciphertext: {ct.hex()}")
    print(f"Decrypted:  {pt}")
    assert message == pt, "CBC Mode fails!"
    print("CBC operations work correctly!")
