# S-AES CBC & Brute Force Project

This repository contains a full from-scratch implementation of the Simplified AES (S-AES) block cipher, operating in Cipher Block Chaining (CBC) mode, along with a Cryptanalysis (Brute Force) demonstration.

This project was developed for the Cryptography assignment to get hands-on experience protecting data and understanding how block ciphers, modes of operation, and brute force attacks work.

## Files Structure

- `saes.py`: The core S-AES engine. Implements the $GF(2^4)$ arithmetic, Key Expansion, SubNibbles, ShiftRows, and MixColumns for 16-bit blocks and 16-bit keys. It includes both encryption and decryption routines.
- `cbc_mode.py`: Implements the Cipher Block Chaining (CBC) mode of operation on top of the S-AES core. Includes PKCS#7-style padding to handle arbitrary file lengths, and provides functions to encrypt/decrypt both raw bytes and files.
- `brute_force.py`: Implements a brute-force attack to retrieve the 16-bit key from a ciphertext given a known Initialization Vector (IV) and a known plaintext header (e.g., intercepting a known file format or a known start of a message).
- `main.py`: The main demonstration script that creates a dummy text file, encrypts it, and then simulates an attacker intercepting the file and brute-forcing the key to decrypt it.

## Requirements

The project uses only the standard Python libraries (no external cryptographic libraries like `PyCryptodome` are used, as per the assignment restrictions).

You need Python 3.6 or later installed.

## Usage

### Running the Full Demonstration

To see the complete workflow (Creation -> Encryption -> Interception -> Brute Force -> Decryption), simply run:

```bash
python main.py
```

This will output the progress in the console and create the following files:
- `sample.txt`: The original plaintext file.
- `sample.enc`: The S-AES CBC encrypted ciphertext.
- `sample_decrypted.txt`: The decrypted file recovered by the brute force attack.

### Running Individual Tests

You can run the modules individually to verify their correctness:

- **Test the S-AES core operations** (verifies against the standard `0x6F6B` / `0xA73B` test vector):
  ```bash
  python saes.py
  ```

- **Test the CBC mode padding and chaining**:
  ```bash
  python cbc_mode.py
  ```

- **Test the Brute Force logic independently**:
  ```bash
  python brute_force.py
  ```

## Report Outline

When writing your detailed report, you can follow these 4 steps based on this code:

1. **Research S-AES**: Explain the 2-round structure of S-AES, the $GF(2^4)$ polynomial $x^4 + x + 1$, and how the block size (16 bits) makes it susceptible to Brute Force ($2^{16} = 65,536$ keys).
2. **S-AES CBC Implementation**: Detail how `saes.py` implements the math without using built-in libraries. Explain how `cbc_mode.py` uses an IV and XORs each plaintext block with the previous ciphertext block. Mention the PKCS#7-style padding used for 2-byte blocks.
3. **Cryptanalysis**: Explain the Brute Force methodology in `brute_force.py`. Emphasize that because the key space is only $2^{16}$, a modern computer can check all possible keys in less than a second. We use a known plaintext attack (knowing the file starts with `"Dear Students,"`) to verify when the correct key is found.
4. **Presentation**: Use the output of `main.py` as a practical demonstration of how data is protected and subsequently compromised when using a small key size.
