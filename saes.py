"""
Simplified AES (S-AES) Implementation in Python.
This module implements the core block cipher operations for a 16-bit block and 16-bit key.
"""

SBOX = [
    0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5,
    0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7
]

INV_SBOX = [
    0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF,
    0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE
]

def gf_add(a, b):
    """Addition in GF(2^4) is just XOR."""
    return a ^ b

def gf_mult(a, b):
    """Multiplication in GF(2^4) with irreducible polynomial x^4 + x + 1 (10011)."""
    p = 0
    for _ in range(4):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x8
        a <<= 1
        if hi_bit_set:
            a ^= 0x13  # x^4 + x + 1
        b >>= 1
    return p & 0xF

def sub_nibbles(byte_val):
    """Applies S-Box to a byte (two nibbles)."""
    n1 = (byte_val >> 4) & 0xF
    n2 = byte_val & 0xF
    return (SBOX[n1] << 4) | SBOX[n2]

def rot_word(byte_val):
    """Swaps the two nibbles in a byte."""
    n1 = (byte_val >> 4) & 0xF
    n2 = byte_val & 0xF
    return (n2 << 4) | n1

def key_expansion(key_16bit):
    """
    Expands a 16-bit key into 3 16-bit round keys.
    Returns a list of 3 round keys (w0|w1, w2|w3, w4|w5).
    """
    w = [0] * 6
    w[0] = (key_16bit >> 8) & 0xFF
    w[1] = key_16bit & 0xFF
    
    # RCON(1) = 0x80, RCON(2) = 0x30
    w[2] = w[0] ^ 0x80 ^ sub_nibbles(rot_word(w[1]))
    w[3] = w[2] ^ w[1]
    
    w[4] = w[2] ^ 0x30 ^ sub_nibbles(rot_word(w[3]))
    w[5] = w[4] ^ w[3]
    
    k0 = (w[0] << 8) | w[1]
    k1 = (w[2] << 8) | w[3]
    k2 = (w[4] << 8) | w[5]
    
    return [k0, k1, k2]

def add_round_key(state, key):
    return state ^ key

def nibble_substitution(state, sbox):
    """Applies the given S-Box to all 4 nibbles in the 16-bit state."""
    n0 = (state >> 12) & 0xF
    n1 = (state >> 8) & 0xF
    n2 = (state >> 4) & 0xF
    n3 = state & 0xF
    return (sbox[n0] << 12) | (sbox[n1] << 8) | (sbox[n2] << 4) | sbox[n3]

def shift_rows(state):
    """
    Swaps the second nibble and the fourth nibble.
    State bits: N0 N1 N2 N3 -> N0 N3 N2 N1
    """
    n0 = state & 0xF000
    n1 = state & 0x0F00
    n2 = state & 0x00F0
    n3 = state & 0x000F
    return n0 | (n3 << 8) | n2 | (n1 >> 8)

def mix_columns(state, is_inverse=False):
    """
    Applies MixColumns transformation.
    Matrix (Encryption): [1 4; 4 1]
    Matrix (Decryption): [9 2; 2 9]
    """
    n0 = (state >> 12) & 0xF
    n1 = (state >> 8) & 0xF
    n2 = (state >> 4) & 0xF
    n3 = state & 0xF

    if not is_inverse:
        # Encryption
        new_n0 = gf_add(gf_mult(1, n0), gf_mult(4, n1))
        new_n1 = gf_add(gf_mult(4, n0), gf_mult(1, n1))
        new_n2 = gf_add(gf_mult(1, n2), gf_mult(4, n3))
        new_n3 = gf_add(gf_mult(4, n2), gf_mult(1, n3))
    else:
        # Decryption
        new_n0 = gf_add(gf_mult(9, n0), gf_mult(2, n1))
        new_n1 = gf_add(gf_mult(2, n0), gf_mult(9, n1))
        new_n2 = gf_add(gf_mult(9, n2), gf_mult(2, n3))
        new_n3 = gf_add(gf_mult(2, n2), gf_mult(9, n3))

    return (new_n0 << 12) | (new_n1 << 8) | (new_n2 << 4) | new_n3

def encrypt_block(plaintext, key):
    """Encrypts a 16-bit plaintext block using a 16-bit key."""
    keys = key_expansion(key)
    
    # Round 0
    state = add_round_key(plaintext, keys[0])
    
    # Round 1
    state = nibble_substitution(state, SBOX)
    state = shift_rows(state)
    state = mix_columns(state, is_inverse=False)
    state = add_round_key(state, keys[1])
    
    # Round 2
    state = nibble_substitution(state, SBOX)
    state = shift_rows(state)
    state = add_round_key(state, keys[2])
    
    return state

def decrypt_block(ciphertext, key):
    """Decrypts a 16-bit ciphertext block using a 16-bit key."""
    keys = key_expansion(key)
    
    # Inverse Round 2
    state = add_round_key(ciphertext, keys[2])
    state = shift_rows(state)
    state = nibble_substitution(state, INV_SBOX)
    
    # Inverse Round 1
    state = add_round_key(state, keys[1])
    state = mix_columns(state, is_inverse=True)
    state = shift_rows(state)
    state = nibble_substitution(state, INV_SBOX)
    
    # Inverse Round 0
    state = add_round_key(state, keys[0])
    
    return state

if __name__ == "__main__":
    # Test vectors
    test_key = 0x2D55
    test_pt = 0xD728
    
    print(f"Plaintext:  0x{test_pt:04X}")
    print(f"Key:        0x{test_key:04X}")
    
    ct = encrypt_block(test_pt, test_key)
    print(f"Ciphertext: 0x{ct:04X}") # Expected: 0x24EC (stallings example)
    
    decrypted = decrypt_block(ct, test_key)
    print(f"Decrypted:  0x{decrypted:04X}")
    assert decrypted == test_pt, "Decryption failed!"
    print("S-AES Block operations work correctly!")
