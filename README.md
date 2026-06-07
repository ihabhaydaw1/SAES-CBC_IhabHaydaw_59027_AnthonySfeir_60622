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
| `main.py` | Full CLI demo — encrypts text + image, runs brute force |
| `app.py` | Flask web application with REST API endpoints |
| `templates/index.html` | Web UI — 4-tab interface for all operations |
| `static/style.css` | Premium dark-mode UI styling |
| `static/script.js` | Frontend logic for all tabs |
| `report.md` | Detailed report covering all 4 project steps |
| `sample.txt` | Sample plaintext file for testing |
| `sample.bmp` | Sample BMP image for testing |

---

## Requirements

- **Python 3.6+**
- **Flask** (`pip install flask`)
- No other external dependencies (only standard library modules: `os`, `time`, `struct`, `random`)

---

## Quick Start

### Web Interface (Recommended)

```bash
pip install flask
python app.py
```

Open **http://localhost:5000** in your browser. The web UI provides 4 tabs:

1. **Encrypt / Decrypt** — Upload files or enter text to encrypt/decrypt with S-AES-CBC
2. **Brute Force Attack** — Upload an encrypted file and attempt to recover the 16-bit key
3. **Cryptanalysis** — Run advanced attacks (KPA, Differential, Linear, Bit-Flipping)

### CLI — Full Demonstration

```bash
python main.py
```

Encrypts a text file and a BMP image using S-AES-CBC, then runs brute force to recover both keys.

### CLI — Cryptanalysis Suite

```bash
python cryptanalysis.py
```

Runs all cryptanalysis demonstrations:
- Known-Plaintext Attack (KPA)
- Differential Cryptanalysis (builds DDT, finds best differentials)
- Linear Cryptanalysis (builds LAT, finds best approximations)
- CBC Bit-Flipping Attack

### CLI — Step 4 Attack

```bash
python step4_attack.py
```

Simulates intercepting another group's S-AES-CBC ciphertext and recovering the key.

### Individual Module Tests

```bash
python saes.py           # Test S-AES block operations
python cbc_mode.py       # Test CBC mode
python brute_force.py    # Test brute force
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

### Cryptanalysis Methods

1. **Known-Plaintext Attack (KPA):** Given a plaintext-ciphertext pair, exhaustively search for the key
2. **Differential Cryptanalysis:** Build DDT, find high-probability differentials, recover last-round key
3. **Linear Cryptanalysis:** Build LAT, find high-bias approximations, recover last-round key
4. **CBC Bit-Flipping:** Modify ciphertext to alter specific plaintext bytes without knowing the key

---

## References

- Stallings, W. *Cryptography and Network Security* — S-AES specification
- Heys, H. *A Tutorial on Linear and Differential Cryptanalysis*
- NIST SP 800-38A — Recommendation for Block Cipher Modes of Operation
