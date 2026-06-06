# S-AES CBC — Encryption, Cryptanalysis & Brute Force

**Course:** IN410 — Cryptography  
**Authors:** Ihab Haydaw (59027), Anthony Sfeir (60622)  
**Project:** S-AES with CBC Mode of Operation

---

## Overview

A complete from-scratch implementation of the **Simplified AES (S-AES)** block cipher operating in **Cipher Block Chaining (CBC)** mode, along with multiple **cryptanalysis** and **brute force** attack demonstrations.

> **Note:** No predefined AES/DES Python libraries are used. The entire cipher is implemented from first principles.

---

## Project Structure

| File | Description |
|------|-------------|
| `saes.py` | Core S-AES engine — GF(2⁴) arithmetic, Key Expansion, SubNibbles, ShiftRows, MixColumns for 16-bit blocks/keys |
| `cbc_mode.py` | CBC mode of operation with PKCS#7 padding, file encrypt/decrypt |
| `brute_force.py` | Exhaustive brute force key recovery (2¹⁶ key space) |
| `cryptanalysis.py` | Advanced attacks: Known-Plaintext, Differential, Linear Cryptanalysis, CBC Bit-Flipping |
| `step4_attack.py` | Step 4: Simulates attacking another group's ciphertext |
| `main.py` | Full demo — encrypts text + image, runs brute force |
| `test.py` | Step-by-step S-AES verification with test vectors |
| `report.md` | Detailed report covering all 4 project steps |

---

## Requirements

- **Python 3.6+**
- No external dependencies (only standard library modules: `os`, `time`, `struct`, `random`)

---

## Quick Start

### 1. Full Demonstration (Encryption + Brute Force)

```bash
python main.py
```

Encrypts a text file and a BMP image using S-AES-CBC, then runs brute force to recover both keys.

### 2. Cryptanalysis Suite

```bash
python cryptanalysis.py
```

Runs all cryptanalysis demonstrations:
- Known-Plaintext Attack (KPA)
- Differential Cryptanalysis (builds DDT, finds best differentials)
- Linear Cryptanalysis (builds LAT, finds best approximations)
- CBC Bit-Flipping Attack

### 3. Step 4 — Attack Another Group's Ciphertext

```bash
python step4_attack.py
```

Simulates intercepting another group's S-AES-CBC ciphertext and recovering the key.

### 4. Individual Module Tests

```bash
python saes.py           # Test S-AES block operations
python cbc_mode.py       # Test CBC mode
python brute_force.py    # Test brute force
python test.py           # Step-by-step encryption trace
```

---

## How It Works

### S-AES (Simplified AES)

- **Block size:** 16 bits (2 bytes)
- **Key size:** 16 bits
- **Rounds:** 2
- **Operations:** SubNibbles (4-bit S-Box), ShiftRows, MixColumns (GF(2⁴)), AddRoundKey
- **Key schedule:** Generates 3 round keys from the 16-bit master key using RCON constants

### CBC Mode

- XORs each plaintext block with the previous ciphertext block (or IV for the first block)
- Uses PKCS#7-style padding for 2-byte blocks
- Provides semantic security (identical plaintext blocks produce different ciphertext)

### Brute Force Attack

- Key space: 2¹⁶ = 65,536 keys → trivially searchable
- Uses known-plaintext header to verify candidate keys
- Typically completes in < 1 second

---

## References

- Stallings, W. *Cryptography and Network Security* — S-AES specification
- Heys, H. *A Tutorial on Linear and Differential Cryptanalysis*
- NIST SP 800-38A — Recommendation for Block Cipher Modes of Operation
