"""
Cryptanalysis Module for S-AES in CBC Mode.

This module implements several cryptanalysis techniques:
1. Known-Plaintext Attack (KPA)
2. Differential Cryptanalysis
3. Linear Cryptanalysis
4. CBC Bit-Flipping Attack

Authors: Ihab Haydaw (59027), Anthony Sfeir (60622)
"""

import time
import random
from saes import (
    encrypt_block, decrypt_block, key_expansion,
    SBOX, INV_SBOX, nibble_substitution, shift_rows,
    mix_columns, add_round_key, gf_mult, gf_add
)
from cbc_mode import encrypt_cbc, decrypt_cbc


# =============================================================================
# 1. KNOWN-PLAINTEXT ATTACK (KPA)
# =============================================================================

def known_plaintext_attack(known_pairs, iv=None, mode="ecb"):
    """
    Known-Plaintext Attack: Given one or more (plaintext, ciphertext) pairs,
    exhaustively search for the key.

    In ECB mode, each pair is a single 16-bit block.
    In CBC mode, the IV is required and the pairs are (plaintext_bytes, ciphertext_bytes).

    Returns the key if found, or None.
    """
    print("=" * 55)
    print("  KNOWN-PLAINTEXT ATTACK (KPA)")
    print("=" * 55)
    start_time = time.time()

    if mode == "ecb":
        # Simple ECB: each pair is (pt_16bit, ct_16bit)
        pt, ct = known_pairs[0]
        print(f"  Known plaintext:  0x{pt:04X}")
        print(f"  Known ciphertext: 0x{ct:04X}")

        for key in range(0x10000):
            if encrypt_block(pt, key) == ct:
                # Verify with additional pairs if available
                valid = True
                for p, c in known_pairs[1:]:
                    if encrypt_block(p, key) != c:
                        valid = False
                        break
                if valid:
                    elapsed = time.time() - start_time
                    print(f"\n  [*] KEY FOUND: 0x{key:04X}")
                    print(f"  [*] Time: {elapsed:.3f}s")
                    print(f"  [*] Keys tested: {key + 1:,}")
                    return key

    elif mode == "cbc":
        # CBC mode: derive the first block's expected encryption output
        # In CBC: C0 = E_k(P0 XOR IV)
        pt_bytes, ct_bytes = known_pairs[0]
        p0 = (pt_bytes[0] << 8) | pt_bytes[1]
        c0 = (ct_bytes[0] << 8) | ct_bytes[1]

        print(f"  Known P0: 0x{p0:04X}, Known C0: 0x{c0:04X}, IV: 0x{iv:04X}")
        xored_input = p0 ^ iv  # This is what gets encrypted to produce C0

        for key in range(0x10000):
            if encrypt_block(xored_input, key) == c0:
                # Verify with second block if available
                if len(ct_bytes) >= 4 and len(pt_bytes) >= 4:
                    p1 = (pt_bytes[2] << 8) | pt_bytes[3]
                    c1 = (ct_bytes[2] << 8) | ct_bytes[3]
                    xored_input_1 = p1 ^ c0
                    if encrypt_block(xored_input_1, key) != c1:
                        continue
                elapsed = time.time() - start_time
                print(f"\n  [*] KEY FOUND: 0x{key:04X}")
                print(f"  [*] Time: {elapsed:.3f}s")
                return key

    elapsed = time.time() - start_time
    print(f"\n  [-] Key not found. Time: {elapsed:.3f}s")
    return None


# =============================================================================
# 2. DIFFERENTIAL CRYPTANALYSIS
# =============================================================================

def build_difference_distribution_table():
    """
    Builds the Difference Distribution Table (DDT) for the S-AES S-Box.
    DDT[dx][dy] = number of input pairs with difference dx that produce output difference dy.
    """
    ddt = [[0] * 16 for _ in range(16)]
    for x in range(16):
        for dx in range(16):
            x_star = x ^ dx  # the paired input
            y = SBOX[x]
            y_star = SBOX[x_star]
            dy = y ^ y_star
            ddt[dx][dy] += 1
    return ddt


def print_ddt(ddt):
    """Pretty prints the Difference Distribution Table."""
    print("\n  Difference Distribution Table (DDT) for S-AES S-Box:")
    print("  " + "-" * 70)
    header = "  Dx\\Dy |"
    for dy in range(16):
        header += f" {dy:2X} "
    print(header)
    print("  " + "-" * 70)
    for dx in range(16):
        row = f"    {dx:2X}  |"
        for dy in range(16):
            val = ddt[dx][dy]
            if val > 0:
                row += f" {val:2d} "
            else:
                row += "  . "
        print(row)
    print("  " + "-" * 70)


def find_best_differentials(ddt):
    """
    Finds the best differential characteristics (highest probability)
    from the DDT, excluding the trivial (0 -> 0) entry.
    """
    differentials = []
    for dx in range(1, 16):  # skip dx=0
        for dy in range(16):
            if ddt[dx][dy] > 0:
                prob = ddt[dx][dy] / 16.0
                differentials.append((dx, dy, ddt[dx][dy], prob))

    differentials.sort(key=lambda x: x[3], reverse=True)
    return differentials


def differential_cryptanalysis_demo(target_key):
    """
    Demonstrates Differential Cryptanalysis on S-AES.

    Approach:
    - Build the DDT to find high-probability differentials through the S-Box.
    - Use chosen plaintext pairs with a specific input difference.
    - Analyze the output differences to recover partial key information.
    - For S-AES with only 2 rounds, we target the last round key.
    """
    print("=" * 55)
    print("  DIFFERENTIAL CRYPTANALYSIS")
    print("=" * 55)
    start_time = time.time()

    # Step 1: Build DDT
    ddt = build_difference_distribution_table()
    print("\n  Step 1: Build Difference Distribution Table")
    print_ddt(ddt)

    # Step 2: Find best differentials
    best = find_best_differentials(ddt)
    print("\n  Step 2: Top 5 differential characteristics:")
    for i, (dx, dy, count, prob) in enumerate(best[:5]):
        print(f"    #{i+1}: Din=0x{dx:X} -> Dout=0x{dy:X}  "
              f"(count={count}/16, prob={prob:.4f})")

    # Step 3: Use the best differential to mount the attack
    # We pick the highest probability differential
    best_dx, best_dy, _, best_prob = best[0]
    print(f"\n  Step 3: Using differential D=0x{best_dx:X} -> 0x{best_dy:X} "
          f"(p={best_prob:.2f})")

    # Step 4: Collect chosen plaintext pairs and count key candidates
    num_pairs = 32
    key_scores = {}  # candidate last-round-key -> score

    print(f"  Step 4: Collecting {num_pairs} chosen plaintext pairs...")

    # Pre-compute all pairs
    pairs = []
    for _ in range(num_pairs):
        p1 = random.randint(0, 0xFFFF)
        input_diff = (best_dx << 12) | (best_dx << 4)
        p2 = p1 ^ input_diff
        c1 = encrypt_block(p1, target_key)
        c2 = encrypt_block(p2, target_key)
        pairs.append((c1, c2))

    print(f"  Step 5: Testing 2^16 key candidates...")

    # Iterate over key candidates (outer loop) with early filtering
    for k2_candidate in range(0x10000):
        score = 0
        for c1, c2 in pairs:
            # Undo last AddRoundKey
            s1 = c1 ^ k2_candidate
            s2 = c2 ^ k2_candidate

            # Undo ShiftRows (it is its own inverse for S-AES)
            s1 = shift_rows(s1)
            s2 = shift_rows(s2)

            # Undo SubNibbles
            s1 = nibble_substitution(s1, INV_SBOX)
            s2 = nibble_substitution(s2, INV_SBOX)

            # Check if difference matches expected after round 1
            diff_after = s1 ^ s2
            actual_n0 = (diff_after >> 12) & 0xF
            actual_n2 = (diff_after >> 4) & 0xF

            if actual_n0 == best_dy and actual_n2 == best_dy:
                score += 1

        if score > 0:
            key_scores[k2_candidate] = score

    # Step 6: Rank candidates
    if key_scores:
        ranked = sorted(key_scores.items(), key=lambda x: x[1], reverse=True)
        actual_keys = key_expansion(target_key)

        print(f"\n  Step 6: Top 5 last-round key candidates:")
        for i, (k, score) in enumerate(ranked[:5]):
            marker = " <-- CORRECT" if k == actual_keys[2] else ""
            print(f"    #{i+1}: K2=0x{k:04X}  score={score}/{num_pairs}{marker}")

        # Check if the correct key is in top candidates
        found_rank = None
        for i, (k, _) in enumerate(ranked):
            if k == actual_keys[2]:
                found_rank = i + 1
                break

        if found_rank:
            print(f"\n  [*] Correct last-round key 0x{actual_keys[2]:04X} "
                  f"found at rank #{found_rank}")
        else:
            print(f"\n  [-] Correct key not found in top candidates "
                  f"(need more pairs)")

    elapsed = time.time() - start_time
    print(f"\n  Total time: {elapsed:.3f}s")
    return ddt


# =============================================================================
# 3. LINEAR CRYPTANALYSIS
# =============================================================================

def build_linear_approximation_table():
    """
    Builds the Linear Approximation Table (LAT) for the S-AES S-Box.
    LAT[a][b] = |{x : a·x = b·S(x)}| - 8
    where a·x means the dot product (XOR of ANDed bits).
    """
    lat = [[0] * 16 for _ in range(16)]

    for input_mask in range(16):
        for output_mask in range(16):
            count = 0
            for x in range(16):
                # Compute parity of input_mask AND x
                input_parity = bin(input_mask & x).count('1') % 2
                # Compute parity of output_mask AND S(x)
                output_parity = bin(output_mask & SBOX[x]).count('1') % 2
                if input_parity == output_parity:
                    count += 1
            lat[input_mask][output_mask] = count - 8  # bias

    return lat


def print_lat(lat):
    """Pretty prints the Linear Approximation Table."""
    print("\n  Linear Approximation Table (LAT) for S-AES S-Box:")
    print("  " + "-" * 70)
    header = "  a\\b   |"
    for b in range(16):
        header += f" {b:2X} "
    print(header)
    print("  " + "-" * 70)
    for a in range(16):
        row = f"    {a:2X}  |"
        for b in range(16):
            val = lat[a][b]
            if val >= 0:
                row += f" +{val} "
            else:
                row += f" {val} "
        print(row)
    print("  " + "-" * 70)


def find_best_linear_approximations(lat):
    """
    Finds the best linear approximations (highest absolute bias)
    from the LAT, excluding the trivial (0, 0) entry.
    """
    approxs = []
    for a in range(16):
        for b in range(16):
            if a == 0 and b == 0:
                continue
            bias = lat[a][b]
            if abs(bias) > 0:
                approxs.append((a, b, bias, abs(bias) / 16.0))

    approxs.sort(key=lambda x: abs(x[2]), reverse=True)
    return approxs


def linear_cryptanalysis_demo(target_key):
    """
    Demonstrates Linear Cryptanalysis on S-AES.

    Approach:
    - Build the LAT to find high-bias linear approximations.
    - Collect known plaintext-ciphertext pairs.
    - Use the linear approximations to derive key bits with statistical analysis.
    """
    print("\n" + "=" * 55)
    print("  LINEAR CRYPTANALYSIS")
    print("=" * 55)
    start_time = time.time()

    # Step 1: Build LAT
    lat = build_linear_approximation_table()
    print("\n  Step 1: Build Linear Approximation Table")
    print_lat(lat)

    # Step 2: Find best approximations
    best = find_best_linear_approximations(lat)
    print("\n  Step 2: Top 5 linear approximations (highest |bias|):")
    for i, (a, b, bias, prob_bias) in enumerate(best[:5]):
        print(f"    #{i+1}: input_mask=0x{a:X}, output_mask=0x{b:X}, "
              f"bias={bias:+d}, |bias|/16={prob_bias:.4f}")

    # Step 3: Use known plaintext-ciphertext pairs to recover key bits
    num_pairs = 200
    print(f"\n  Step 3: Collecting {num_pairs} known PT-CT pairs...")

    # For each candidate partial key, count how many pairs satisfy the
    # linear relation
    best_a, best_b = best[0][0], best[0][1]
    print(f"  Using approximation: input_mask=0x{best_a:X}, "
          f"output_mask=0x{best_b:X}")

    key_counts = {}

    pairs = []
    for _ in range(num_pairs):
        pt = random.randint(0, 0xFFFF)
        ct = encrypt_block(pt, target_key)
        pairs.append((pt, ct))

    print(f"  Step 4: Testing 2^16 key candidates...")

    # Try each possible last round key
    for k2_candidate in range(0x10000):
        count = 0
        for pt, ct in pairs:
            # Partially decrypt through the last round
            state = ct ^ k2_candidate
            state = shift_rows(state)
            state = nibble_substitution(state, INV_SBOX)

            # Check linear relation between pt and state (output of round 1)
            # Using the best approximation on nibbles
            pt_n0 = (pt >> 12) & 0xF
            st_n0 = (state >> 12) & 0xF

            lhs = bin(best_a & pt_n0).count('1') % 2
            rhs = bin(best_b & st_n0).count('1') % 2

            if lhs == rhs:
                count += 1

        key_counts[k2_candidate] = abs(count - num_pairs // 2)

    # Rank by highest deviation from expected (N/2)
    ranked = sorted(key_counts.items(), key=lambda x: x[1], reverse=True)
    actual_keys = key_expansion(target_key)

    print(f"\n  Step 5: Top 5 last-round key candidates (by bias):")
    for i, (k, score) in enumerate(ranked[:5]):
        marker = " <-- CORRECT" if k == actual_keys[2] else ""
        print(f"    #{i+1}: K2=0x{k:04X}  deviation={score}{marker}")

    found_rank = None
    for i, (k, _) in enumerate(ranked):
        if k == actual_keys[2]:
            found_rank = i + 1
            break

    if found_rank and found_rank <= 10:
        print(f"\n  [*] Correct key 0x{actual_keys[2]:04X} found at rank #{found_rank}")
    else:
        rank_str = f"#{found_rank}" if found_rank else "not found"
        print(f"\n  [~] Correct key rank: {rank_str} (statistical -- more pairs may help)")

    elapsed = time.time() - start_time
    print(f"\n  Total time: {elapsed:.3f}s")
    return lat


# =============================================================================
# 4. CBC BIT-FLIPPING ATTACK
# =============================================================================

def cbc_bit_flipping_demo(key, iv):
    """
    Demonstrates a CBC Bit-Flipping Attack.

    In CBC mode, flipping bit i in ciphertext block C_{n-1} will:
    - Corrupt the decryption of block n-1 (random garbage)
    - Flip exactly bit i in the plaintext of block n

    This allows an attacker to modify specific plaintext bytes without
    knowing the key.
    """
    print("\n" + "=" * 55)
    print("  CBC BIT-FLIPPING ATTACK")
    print("=" * 55)

    # Original message (multiple blocks)
    original = b"role=user"
    print(f"\n  Original plaintext: {original}")

    # Encrypt
    ct = encrypt_cbc(original, key, iv)
    print(f"  Ciphertext (hex):   {ct.hex()}")

    # Decrypt normally to verify
    pt = decrypt_cbc(ct, key, iv)
    print(f"  Normal decryption:  {pt}")

    # --- Attack: change "user" to "root" in the plaintext ---
    # "user" starts at byte index 5 in "role=user"
    # In CBC, to flip plaintext byte P[i] in block n, we flip C[i] in block n-1
    # For 2-byte blocks:
    #   Block layout: [ro] [le] [=u] [se] [r\x01]  (with padding)
    #   If we want to change byte at position 5 ('u') to 'r':
    #   We XOR the corresponding byte in the previous ciphertext block

    ct_array = bytearray(ct)

    # Target: change 'u' (0x75) at position 5 to 'r' (0x72)
    # Position 5 is in block 2 (0-indexed), so we modify ciphertext block 1
    # The byte to flip is at ct_array[2] (block 1, first byte maps to block 2, second byte)
    # Actually for 2-byte blocks:
    #   Block 0: ct[0:2], Block 1: ct[2:4], Block 2: ct[4:6], ...
    #   Plaintext block 2 = Decrypt(ct_block2) XOR ct_block1
    # "role=user\x01"  -> blocks: "ro", "le", "=u", "se", "r\x01"
    # We want to change "=u" to "=r" -> modify ct block 1 (bytes 2,3)
    # To change the second byte of block 2 ('u' -> 'r'):
    #   flip = ord('u') XOR ord('r') = 0x07
    #   ct_array[3] ^= flip  (byte index 3 is second byte of block 1)

    target_block = 2  # block containing "=u"
    target_byte_in_block = 1  # second byte ('u')
    prev_block_byte_idx = (target_block - 1) * 2 + target_byte_in_block

    flip_mask = ord('u') ^ ord('r')  # 0x07
    ct_array[prev_block_byte_idx] ^= flip_mask

    print(f"\n  --- Attacker modifies ciphertext ---")
    print(f"  Flipped byte at position {prev_block_byte_idx} with mask 0x{flip_mask:02X}")
    print(f"  Modified ciphertext (hex): {bytes(ct_array).hex()}")

    # Decrypt the modified ciphertext
    try:
        modified_pt = decrypt_cbc(bytes(ct_array), key, iv)
        print(f"  Modified plaintext: {modified_pt}")

        # Show the effect
        print(f"\n  [*] Original byte at target position: '{chr(original[5])}' (0x{original[5]:02X})")
        if len(modified_pt) > 5:
            print(f"  [*] Modified byte at target position: '{chr(modified_pt[5])}' (0x{modified_pt[5]:02X})")

        # Note: the previous block will be garbled
        print(f"\n  [!] Note: Block {target_block - 1} (previous block) is corrupted")
        print(f"      as a side effect (this is expected in bit-flipping attacks).")
    except Exception as e:
        print(f"  Modified plaintext decryption raised: {e}")
        print(f"  (Padding may be corrupted -- this is expected in some cases)")

    print(f"\n  [*] Conclusion: An attacker can modify specific plaintext")
    print(f"      bytes without knowing the key, but at the cost of")
    print(f"      corrupting the previous plaintext block.")


# =============================================================================
# MAIN -- Run all demonstrations
# =============================================================================

if __name__ == "__main__":
    print("=" * 55)
    print("  S-AES CRYPTANALYSIS SUITE")
    print("=" * 55)

    demo_key = 0x3A94
    demo_iv = 0xBEEF

    # 1. Known-Plaintext Attack (ECB mode for simplicity)
    print("\n")
    pt_block = 0x6F6B
    ct_block = encrypt_block(pt_block, demo_key)
    kpa_result = known_plaintext_attack(
        [(pt_block, ct_block)], mode="ecb"
    )
    if kpa_result is not None:
        print(f"  Verification: encrypt(0x{pt_block:04X}, 0x{kpa_result:04X}) "
              f"= 0x{encrypt_block(pt_block, kpa_result):04X}")

    # 2. Differential Cryptanalysis
    print("\n")
    differential_cryptanalysis_demo(demo_key)

    # 3. Linear Cryptanalysis
    print("\n")
    linear_cryptanalysis_demo(demo_key)

    # 4. CBC Bit-Flipping Attack
    print("\n")
    cbc_bit_flipping_demo(demo_key, demo_iv)

    print("\n" + "=" * 55)
    print("  ALL CRYPTANALYSIS DEMOS COMPLETE")
    print("=" * 55)
