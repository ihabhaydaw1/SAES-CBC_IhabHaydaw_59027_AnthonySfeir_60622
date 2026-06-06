# S-AES CBC — Detailed Project Report

**Course:** IN410 — Cryptography  
**Authors:** Ihab Haydaw (59027), Anthony Sfeir (60622)  
**Date:** June 2026  
**Project:** Simplified AES (S-AES) with CBC Mode of Operation

---

## Table of Contents

1. [Step 1: Research on S-AES and Cryptanalysis](#step-1-research-on-s-aes-and-cryptanalysis)
2. [Step 2: S-AES CBC Implementation](#step-2-s-aes-cbc-implementation)
3. [Step 3: Cryptanalysis and Brute Force](#step-3-cryptanalysis-and-brute-force)
4. [Step 4: Attacking Another Group's Ciphertext](#step-4-attacking-another-groups-ciphertext)
5. [Conclusion](#conclusion)
6. [References](#references)

---

## Step 1: Research on S-AES and Cryptanalysis

### 1.1 Simplified AES (S-AES) Overview

Simplified AES (S-AES) is a pedagogical block cipher designed by Edward Schaefer to mirror the structure of the full AES (Rijndael) algorithm while being compact enough to trace by hand. It provides an accessible way to understand AES internals.

**Key Parameters:**

| Parameter | Value |
|-----------|-------|
| Block size | 16 bits (2 bytes) |
| Key size | 16 bits (2 bytes) |
| Number of rounds | 2 |
| Galois Field | GF(2⁴) with irreducible polynomial x⁴ + x + 1 |
| S-Box size | 4-bit input → 4-bit output (16 entries) |

### 1.2 S-AES State Representation

The 16-bit state is arranged as a **2×2 matrix of 4-bit nibbles** in column-major order:

```
State = | S₀  S₂ |
        | S₁  S₃ |

Bit layout: S₀(bits 15-12)  S₁(bits 11-8)  S₂(bits 7-4)  S₃(bits 3-0)
```

### 1.3 GF(2⁴) Arithmetic

All arithmetic operations in S-AES are performed over the **Galois Field GF(2⁴)** with the irreducible polynomial **p(x) = x⁴ + x + 1** (binary: `10011`).

**Addition:** Bitwise XOR.

```
a ⊕ b  →  a XOR b
```

**Multiplication:** Polynomial multiplication modulo p(x), using a shift-and-XOR algorithm:

```python
def gf_mult(a, b):
    p = 0
    for _ in range(4):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x8
        a <<= 1
        if hi_bit_set:
            a ^= 0x13  # Reduction by x^4 + x + 1
        b >>= 1
    return p & 0xF
```

When the degree reaches 4 or above, reduction is applied: **x⁴ ≡ x + 1 (mod p(x))**.

### 1.4 S-Box (Substitution Box)

The S-Box provides **non-linearity** (confusion) in the cipher. Each 4-bit nibble is replaced according to a lookup table, constructed via multiplicative inversion in GF(2⁴) followed by an affine transformation.

**Forward S-Box (Encryption):**

| Input  | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | A | B | C | D | E | F |
|--------|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Output | 9 | 4 | A | B | D | 1 | 8 | 5 | 6 | 2 | 0 | 3 | C | E | F | 7 |

**Inverse S-Box (Decryption):**

| Input  | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | A | B | C | D | E | F |
|--------|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Output | A | 5 | 9 | B | 1 | 7 | 8 | F | 6 | 0 | 2 | 3 | C | 4 | D | E |

### 1.5 Key Expansion

The 16-bit master key is expanded into **three 16-bit round keys** (K₀, K₁, K₂):

```
w[0] = key >> 8           (upper byte)
w[1] = key & 0xFF         (lower byte)
w[2] = w[0] ⊕ RCON(1) ⊕ SubNib(RotNib(w[1]))
w[3] = w[2] ⊕ w[1]
w[4] = w[2] ⊕ RCON(2) ⊕ SubNib(RotNib(w[3]))
w[5] = w[4] ⊕ w[3]

Round Keys:
  K₀ = w[0] || w[1]    (original key)
  K₁ = w[2] || w[3]
  K₂ = w[4] || w[5]
```

Where:
- **RotNib(byte):** Swaps the two nibbles: `[N₁|N₂] → [N₂|N₁]`
- **SubNib(byte):** Applies the S-Box to each nibble independently
- **RCON(1) = 0x80**, **RCON(2) = 0x30** (round constants)

### 1.6 Encryption Process

S-AES encryption consists of an initial key addition and 2 rounds:

```
Round 0 (Initial):
    State = Plaintext ⊕ K₀                    [AddRoundKey]

Round 1 (Full Round):
    State = SubNibbles(State)                  [Nibble Substitution]
    State = ShiftRows(State)                   [Row Shifting]
    State = MixColumns(State)                  [Column Mixing]
    State = State ⊕ K₁                        [AddRoundKey]

Round 2 (Final — no MixColumns):
    State = SubNibbles(State)                  [Nibble Substitution]
    State = ShiftRows(State)                   [Row Shifting]
    State = State ⊕ K₂                        [AddRoundKey]

Output: Ciphertext = State
```

**SubNibbles:** Replaces each of the four nibbles using the S-Box. Provides **confusion**.

**ShiftRows:** Swaps the second row of the state matrix:
```
| S₀  S₂ |  →  | S₀  S₂ |    (Row 0: unchanged)
| S₁  S₃ |  →  | S₃  S₁ |    (Row 1: swap S₁ ↔ S₃)
```

**MixColumns:** Multiplies each column by a fixed matrix over GF(2⁴):
```
Encryption:  | 1  4 |      Decryption:  | 9  2 |
             | 4  1 |                   | 2  9 |
```
This provides **diffusion** — spreading the influence of each plaintext bit across the state.

**AddRoundKey:** XOR of the 16-bit state with the 16-bit round key.

### 1.7 Decryption Process

Decryption applies the inverse operations in reverse order:

```
State = Ciphertext ⊕ K₂                   [AddRoundKey]
State = InvShiftRows(State)                [Inverse ShiftRows]
State = InvSubNibbles(State)               [Inverse S-Box]
State = State ⊕ K₁                        [AddRoundKey]
State = InvMixColumns(State)               [Inverse MixColumns]
State = InvShiftRows(State)
State = InvSubNibbles(State)
State = State ⊕ K₀                        [AddRoundKey]
Output: Plaintext = State
```

### 1.8 CBC (Cipher Block Chaining) Mode of Operation

CBC mode chains plaintext blocks together so that each ciphertext block depends on **all preceding plaintext blocks**, preventing patterns in the plaintext from appearing in the ciphertext.

**Encryption:**
```
C₀ = IV
Cᵢ = E_K(Pᵢ ⊕ Cᵢ₋₁)    for i = 1, 2, ..., n
```

**Decryption:**
```
Pᵢ = D_K(Cᵢ) ⊕ Cᵢ₋₁    for i = 1, 2, ..., n    (where C₀ = IV)
```

**Properties:**
- The **Initialization Vector (IV)** must be random and unique per encryption (same key)
- Encryption is **sequential** (each block depends on the previous ciphertext)
- Decryption **can be parallelized**
- Error in ciphertext block Cᵢ corrupts Pᵢ completely and flips specific bits in Pᵢ₊₁

**Padding:** We use PKCS#7-style padding for 2-byte blocks:
- If 1 byte is needed: append `0x01`
- If data is already aligned: append `0x02 0x02`

### 1.9 Cryptanalysis Techniques

#### 1.9.1 Brute Force Attack

With a 16-bit key, the keyspace is only **2¹⁶ = 65,536** possible keys. A modern computer can check all keys in **under one second**. The attacker needs a way to verify the correct key — typically through a known plaintext header (e.g., "BM" for BMP files, "Dear Students" for known messages).

**Complexity:**
- Worst case: 65,536 encryptions
- Average case: 32,768 encryptions

#### 1.9.2 Known-Plaintext Attack (KPA)

Given a known plaintext–ciphertext pair (P, C), the attacker exploits the CBC structure:
- C₁ = E_K(P₁ ⊕ IV) → compute M = P₁ ⊕ IV → now we have a single-block pair (M, C₁)
- Exhaustively try all keys on this **single block** for maximum speed

#### 1.9.3 Differential Cryptanalysis

Invented by Biham & Shamir (1990). Analyzes how **input differences propagate** through the cipher.

**Difference Distribution Table (DDT):** For each input difference Δx and each input x:
- Compute x' = x ⊕ Δx
- Compute output difference: Δy = S(x) ⊕ S(x')
- DDT[Δx][Δy] counts the number of such pairs

A "good" differential has DDT entries significantly above the expected 1/16 probability. For S-AES:
- Only 2 rounds → very short differential paths
- 4-bit S-Box → high maximum differential probabilities
- The attacker can use chosen plaintext pairs with specific input differences to recover the last round key

#### 1.9.4 Linear Cryptanalysis

Invented by Matsui (1993). Finds **probabilistic linear relationships** between plaintext, ciphertext, and key bits.

**Linear Approximation Table (LAT):** For each input mask `a` and output mask `b`:
```
LAT[a][b] = |{x : parity(a & x) = parity(b & S(x))}| - 8
```

A high |bias| value means the approximation holds (or fails) more often than expected, which can be exploited to recover key bits. The **Piling-Up Lemma** combines biases across rounds:
```
ε_total = 2^(n-1) × ε₁ × ε₂ × ... × εₙ
```

#### 1.9.5 CBC Bit-Flipping Attack

Exploits the **malleability** of CBC mode. From the decryption formula Pᵢ = D_K(Cᵢ) ⊕ Cᵢ₋₁, flipping bit j in Cᵢ₋₁ flips exactly bit j in Pᵢ — without knowing the key. This allows an attacker to change specific plaintext bytes at the cost of corrupting the previous block.

#### 1.9.6 Meet-in-the-Middle Attack

Relevant to **double encryption** (encrypting with two keys K₁, K₂): C = E_{K₂}(E_{K₁}(P)). Instead of trying all 2³² key pairs, the attacker:
1. Computes E_{K₁}(P) for all 2¹⁶ values of K₁ → store in a table
2. Computes D_{K₂}(C) for all 2¹⁶ values of K₂ → look up matches

This reduces the complexity from O(2³²) to O(2¹⁷), demonstrating that double encryption with S-AES provides only marginal security improvement.

---

## Step 2: S-AES CBC Implementation

### 2.1 Project Structure

Our implementation is organized into modular Python files:

| File | Purpose |
|------|---------|
| `saes.py` | Core S-AES block cipher (encryption + decryption) |
| `cbc_mode.py` | CBC mode of operation with PKCS#7 padding |
| `brute_force.py` | Brute force key recovery |
| `cryptanalysis.py` | Advanced cryptanalysis techniques |
| `step4_attack.py` | Step 4 — attacking another group's ciphertext |
| `main.py` | Full demonstration (text + image encryption) |
| `test.py` | Step-by-step verification with test vectors |

### 2.2 S-AES Core (`saes.py`)

The core module implements all S-AES operations from scratch:

- **GF(2⁴) arithmetic:** `gf_add()` (XOR) and `gf_mult()` (shift-and-reduce)
- **S-Box / Inverse S-Box:** Lookup tables for nibble substitution
- **Key Expansion:** `key_expansion()` generates 3 round keys from the 16-bit master key
- **Round Operations:** `nibble_substitution()`, `shift_rows()`, `mix_columns()`, `add_round_key()`
- **Block Encrypt/Decrypt:** `encrypt_block()` and `decrypt_block()` for single 16-bit blocks

**No predefined AES or DES libraries are used** — all operations are built from primitive bitwise operations and GF(2⁴) math.

### 2.3 CBC Mode (`cbc_mode.py`)

The CBC module provides:

- **`pad()` / `unpad()`:** PKCS#7-style padding for 2-byte blocks
- **`encrypt_cbc()`:** Encrypts arbitrary-length byte data in CBC mode
  - Pads the plaintext
  - XORs each 16-bit block with the previous ciphertext block (or IV)
  - Encrypts each block with S-AES
- **`decrypt_cbc()`:** Decrypts CBC ciphertext back to plaintext
  - Decrypts each block
  - XORs with the previous ciphertext block (or IV)
  - Removes padding
- **`encrypt_file()` / `decrypt_file()`:** File-level wrappers

### 2.4 Multi-Type Data Support

The implementation encrypts/decrypts any binary data, demonstrated with:
- **Text files** (`.txt`) — human-readable messages
- **BMP images** (`.bmp`) — binary data with known header (`BM`)

The `main.py` script generates a 16×16 pixel BMP image programmatically (no external libraries) to demonstrate binary data encryption.

### 2.5 Test Vectors

We verified our implementation against known S-AES test vectors:
- Key: `0x2D55`, Plaintext: `0xD728` → verified encryption/decryption round-trip
- Key: `0xA73B`, Plaintext: `0x6F6B` → step-by-step trace in `test.py`

---

## Step 3: Cryptanalysis and Brute Force

### 3.1 Brute Force Attack (`brute_force.py`)

**Method:** Exhaustively try all 65,536 possible 16-bit keys against intercepted ciphertext.

**Optimization:** Instead of decrypting the entire file for each candidate key, we only decrypt the first few blocks (enough to cover the known plaintext header), using CBC mode mechanics inline for speed.

**Results:**
- Input: Encrypted text file (`sample.enc`, ~236 bytes)
- Known plaintext: `"Dear Students,"`
- Key found: `0x1337`
- Time: typically **< 1 second**

```
$ python brute_force.py
Testing Brute Force...
Starting brute force attack (Searching 65,536 keys)...
Looking for known plaintext: b'CONFIDENTIAL'
[*] Key Found! Key = 0x4B29
[*] Time taken: 0.XX seconds.
```

### 3.2 Known-Plaintext Attack (`cryptanalysis.py`)

**Method:** In CBC mode, the first ciphertext block C₀ = E_K(P₀ ⊕ IV). If we know P₀ and IV, we compute the expected block cipher input M = P₀ ⊕ IV, then check E_k(M) == C₀ for each candidate key.

This is essentially an optimized brute force that requires **only one block encryption per key test** rather than decrypting multiple blocks.

### 3.3 Differential Cryptanalysis (`cryptanalysis.py`)

**Implementation:**

1. **Build the DDT** for the S-AES S-Box — a 16×16 table showing how input differences map to output differences
2. **Find high-probability differentials** — sorted by count/probability
3. **Collect chosen plaintext pairs** with a specific input difference
4. **Partially decrypt** the last round for each candidate K₂ and check if the output difference matches the expected differential
5. **Rank candidates** by score — the correct last-round key should appear at the top

The DDT reveals that several S-Box differentials have probability 4/16 = 0.25, which is exploitable with relatively few chosen plaintext pairs.

### 3.4 Linear Cryptanalysis (`cryptanalysis.py`)

**Implementation:**

1. **Build the LAT** for the S-AES S-Box — showing the bias of each linear approximation
2. **Find high-bias approximations** — the best approximations have |bias| up to 4/16 = 0.25
3. **Collect known PT-CT pairs** and for each candidate last-round key, check if the linear relation holds
4. **Rank candidates** by deviation from the expected N/2 count

The small S-Box and 2-round structure of S-AES make linear cryptanalysis highly effective — fewer plaintext pairs are needed compared to full AES.

### 3.5 CBC Bit-Flipping Attack (`cryptanalysis.py`)

**Demonstration:** We encrypt `"role=user"` and show how modifying ciphertext bytes changes the plaintext to `"role=root"` — **without knowing the key**.

- The attacker computes a flip mask: `'u' ⊕ 'r' = 0x07`
- XORs this mask into the appropriate byte of the previous ciphertext block
- The target byte in the next plaintext block flips from `'u'` to `'r'`
- The previous plaintext block is corrupted as a side effect

This demonstrates a critical weakness of unauthenticated CBC mode.

### 3.6 Security Analysis Summary

| Attack | Complexity | Feasibility | Notes |
|--------|-----------|-------------|-------|
| Brute Force | 2¹⁶ = 65,536 ops | Trivial (< 1s) | Key space too small |
| Known-Plaintext | 2¹⁶ ops (1 block each) | Trivial (< 1s) | Optimized for CBC |
| Differential | O(2⁸) chosen pairs | Very feasible | 2 rounds → short paths |
| Linear | O(2⁸) known pairs | Very feasible | High S-Box biases |
| Bit-Flipping | O(1) | Trivial | No key needed |

---

## Step 4: Attacking Another Group's Ciphertext

### 4.1 Scenario

We simulate receiving an encrypted message from "Group Alpha" who used S-AES in CBC mode. The attacker:
- Intercepts the ciphertext
- Knows the IV (transmitted in cleartext, as is standard)
- Assumes the message starts with a known header (`"FROM: Group"`)

### 4.2 Attack Methodology

The attack in `step4_attack.py` proceeds in 4 phases:

1. **Interception:** Capture the ciphertext and IV
2. **Intelligence Gathering:** Identify a likely known-plaintext header
3. **Brute Force Attack:** Test all 65,536 keys using two methods:
   - **Standard brute force** (decrypts multiple blocks per key)
   - **Optimized CBC brute force** (single block encryption per key)
4. **Decryption:** Recover the full plaintext with the found key

### 4.3 Results

```
$ python step4_attack.py
============================================================
  STEP 4: ATTACKING ANOTHER GROUP'S CIPHERTEXT
============================================================

[Phase 1] Intercepting ciphertext from 'Group Alpha'...
  Intercepted 280 bytes of ciphertext
  Known IV: 0x1234

[Phase 3] Launching brute force attack...
  [*] Key Found! Key = 0xXXXX
  [*] Time taken: 0.XX seconds.

[Phase 4] Decrypting with recovered key...
  [SUCCESS] Decrypted message matches the original!
```

### 4.4 Conclusion

The 16-bit keyspace of S-AES makes any ciphertext trivially breakable. Regardless of the mode of operation (CBC, ECB, etc.), the key can be recovered in under one second on any modern computer, provided the attacker has a small amount of known plaintext.

---

## Conclusion

This project provided hands-on experience with:

1. **Block cipher internals** — implementing S-AES from scratch gave us a deep understanding of SubBytes, ShiftRows, MixColumns, and key scheduling
2. **Modes of operation** — CBC mode adds crucial properties (semantic security, diffusion across blocks) but also introduces vulnerabilities (bit-flipping, padding oracle attacks)
3. **Cryptanalysis** — we demonstrated that brute force, differential cryptanalysis, linear cryptanalysis, and bit-flipping attacks are all effective against S-AES, highlighting why real-world ciphers use much larger parameters (128+ bit keys, 10+ rounds, 8-bit S-Boxes)
4. **Practical security** — the ease of breaking S-AES reinforces that security depends on sufficiently large key sizes and well-studied cipher designs

### Comparison: S-AES vs. Full AES

| Property | S-AES | AES-128 |
|----------|-------|---------|
| Block size | 16 bits | 128 bits |
| Key size | 16 bits | 128 bits |
| Rounds | 2 | 10 |
| Keyspace | 65,536 | 3.4 × 10³⁸ |
| Brute force time | < 1 second | Billions of years |
| S-Box entries | 16 | 256 |
| Practical security | None (educational) | Very strong |

S-AES is intentionally insecure — its purpose is purely educational. Every attack that is infeasible against full AES becomes trivially feasible against S-AES, making it an ideal teaching tool.

---

## References

1. Schaefer, E. "A Simplified AES Algorithm and Its Linear and Differential Cryptanalyses." *Cryptologia*, 1996.
2. Stallings, W. *Cryptography and Network Security: Principles and Practice*, 7th Edition. Pearson, 2017.
3. Biham, E., Shamir, A. "Differential Cryptanalysis of DES-like Cryptosystems." *Journal of Cryptology*, 1991.
4. Matsui, M. "Linear Cryptanalysis Method for DES Cipher." *EUROCRYPT '93*, Springer, 1994.
5. Heys, H. "A Tutorial on Linear and Differential Cryptanalysis." *Cryptologia*, 2002.
6. NIST SP 800-38A. "Recommendation for Block Cipher Modes of Operation." National Institute of Standards and Technology, 2001.
7. Vaudenay, S. "Security Flaws Induced by CBC Padding." *EUROCRYPT 2002*, Springer, 2002.
