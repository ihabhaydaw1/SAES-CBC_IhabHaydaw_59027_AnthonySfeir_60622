"""
Step 4: Attacking Another Group's Ciphertext

This script simulates receiving an encrypted file from another group
and attempting to recover the key using the cryptanalysis techniques
developed in Step 1.

Scenario:
- Another group encrypted a message using S-AES in CBC mode.
- We intercept the ciphertext and know the IV (typically shared publicly).
- We assume a known-plaintext header (e.g., the file starts with a known string).
- We apply brute force + known-plaintext attack to recover the 16-bit key.
- We then decrypt the full message.

Authors: Ihab Haydaw (59027), Anthony Sfeir (60622)
"""

import time
import random
from saes import encrypt_block, decrypt_block
from cbc_mode import encrypt_cbc, decrypt_cbc, BLOCK_SIZE_BYTES
from brute_force import brute_force_attack


def simulate_other_group_encryption():
    """
    Simulates another group's encryption process.
    They encrypt a message with a random key and a known IV.
    Returns (ciphertext, iv, original_plaintext, secret_key).
    """
    # The "other group's" secret key (unknown to us as attackers)
    secret_key = random.randint(0, 0xFFFF)
    iv = 0x1234  # IV is typically transmitted alongside the ciphertext

    # The message they encrypted
    message = (
        b"FROM: Group Alpha\n"
        b"TO: Professor\n"
        b"SUBJECT: Crypto Assignment\n\n"
        b"Dear Professor,\n\n"
        b"We have completed our S-AES implementation.\n"
        b"Our test results show 100% accuracy on all test vectors.\n"
        b"The brute force attack takes approximately 0.5 seconds.\n\n"
        b"Best Regards,\n"
        b"Group Alpha"
    )

    ciphertext = encrypt_cbc(message, secret_key, iv)
    return ciphertext, iv, message, secret_key


def optimized_cbc_brute_force(ciphertext, iv, known_header):
    """
    Optimized brute force attack for CBC mode.
    Uses the known header to verify candidate keys efficiently.

    Key insight: In CBC mode, C0 = E_k(P0 XOR IV)
    So we can compute the expected input to the block cipher
    and compare E_k(P0 XOR IV) == C0 for each candidate key.
    This only requires ONE block encryption per key candidate.
    """
    print("\n  [*] Running Optimized CBC Brute Force...")
    print(f"  [*] Known header: {known_header[:20]}...")
    print(f"  [*] IV: 0x{iv:04X}")
    start_time = time.time()

    # Extract the first plaintext block and first ciphertext block
    p0 = (known_header[0] << 8) | known_header[1]
    c0 = (ciphertext[0] << 8) | ciphertext[1]

    # In CBC: C0 = E_k(P0 XOR IV)
    expected_input = p0 ^ iv

    # Single-block test for speed
    candidates = []
    for key in range(0x10000):
        if encrypt_block(expected_input, key) == c0:
            candidates.append(key)

    # Verify candidates with the second block
    verified_key = None
    if len(known_header) >= 4:
        p1 = (known_header[2] << 8) | known_header[3]
        c1 = (ciphertext[2] << 8) | ciphertext[3]
        for key in candidates:
            expected_input_1 = p1 ^ c0
            if encrypt_block(expected_input_1, key) == c1:
                verified_key = key
                break
    elif candidates:
        verified_key = candidates[0]

    elapsed = time.time() - start_time

    if verified_key is not None:
        print(f"\n  [*] KEY FOUND: 0x{verified_key:04X}")
        print(f"  [*] Time: {elapsed:.4f} seconds")
        print(f"  [*] Method: CBC-optimized single-block brute force")
        return verified_key
    else:
        print(f"\n  [-] Key not found in {elapsed:.4f} seconds")
        return None


def main():
    print("=" * 60)
    print("  STEP 4: ATTACKING ANOTHER GROUP'S CIPHERTEXT")
    print("=" * 60)

    # Phase 1: Simulate receiving the other group's ciphertext
    print("\n[Phase 1] Intercepting ciphertext from 'Group Alpha'...")
    ciphertext, iv, original_message, actual_key = simulate_other_group_encryption()

    print(f"  Intercepted {len(ciphertext)} bytes of ciphertext")
    print(f"  Known IV: 0x{iv:04X}")
    print(f"  Ciphertext preview (hex): {ciphertext[:20].hex()}...")
    print(f"  (The actual key 0x{actual_key:04X} is UNKNOWN to us)")

    # Phase 2: Gather intelligence
    print("\n[Phase 2] Intelligence gathering...")
    print("  Assumption: Messages from this group start with 'FROM: Group'")
    print("  This is our known-plaintext for the attack.")
    known_header = b"FROM: Group"

    # Phase 3: Attack using brute force
    print("\n[Phase 3] Launching brute force attack...")

    # Method A: Standard brute force (from brute_force.py)
    print("\n  --- Method A: Standard Brute Force ---")
    found_key_a = brute_force_attack(ciphertext, iv, known_header)

    # Method B: Optimized CBC-specific attack
    print("\n  --- Method B: Optimized CBC Brute Force ---")
    found_key_b = optimized_cbc_brute_force(ciphertext, iv, known_header)

    # Use whichever succeeded
    found_key = found_key_a or found_key_b

    # Phase 4: Decrypt the message
    if found_key is not None:
        print(f"\n[Phase 4] Decrypting with recovered key 0x{found_key:04X}...")
        decrypted = decrypt_cbc(ciphertext, found_key, iv)

        print("\n  +---------------------------------------------+")
        print("  |         DECRYPTED MESSAGE                   |")
        print("  +---------------------------------------------+")
        for line in decrypted.decode('utf-8', errors='replace').split('\n'):
            print(f"  |  {line:<42s}|")
        print("  +---------------------------------------------+")

        # Verify
        if decrypted == original_message:
            print("\n  [SUCCESS] Decrypted message matches the original!")
            print(f"  [SUCCESS] Recovered key: 0x{found_key:04X} "
                  f"== Actual key: 0x{actual_key:04X}")
        else:
            print("\n  [PARTIAL] Message recovered but may have minor differences.")
    else:
        print("\n  [FAIL] Could not recover the key.")

    # Phase 5: Summary
    print("\n" + "=" * 60)
    print("  STEP 4 SUMMARY")
    print("=" * 60)
    print(f"  Target:          Group Alpha's S-AES-CBC ciphertext")
    print(f"  Ciphertext size: {len(ciphertext)} bytes")
    print(f"  IV:              0x{iv:04X}")
    print(f"  Key recovered:   0x{found_key:04X}" if found_key else
          "  Key recovered:   FAILED")
    print(f"  Actual key:      0x{actual_key:04X}")
    print(f"  Key space:       2^16 = 65,536 possible keys")
    print(f"  Attack method:   Known-plaintext brute force")
    print(f"  Conclusion:      16-bit keys are trivially breakable!")
    print("=" * 60)


if __name__ == "__main__":
    main()
