"""
S-AES CBC Mode — Flask Web Application

Provides REST API endpoints for:
  1. Encrypt / Decrypt files and text
  2. Brute Force Attack (key recovery)
  3. Cryptanalysis demonstrations (KPA, Differential, Linear, Bit-Flipping)
  4. Step 4 — Attack another group's ciphertext

Authors: Ihab Haydaw (59027), Anthony Sfeir (60622)
"""

import os
import io
import uuid
import time
import random
from flask import Flask, request, jsonify, render_template, send_file
from werkzeug.utils import secure_filename

from saes import encrypt_block, decrypt_block, key_expansion, SBOX, INV_SBOX
from saes import nibble_substitution, shift_rows
from cbc_mode import encrypt_cbc, decrypt_cbc, encrypt_file, decrypt_file
from brute_force import brute_force_attack
from cryptanalysis import (
    known_plaintext_attack,
    build_difference_distribution_table,
    find_best_differentials,
    build_linear_approximation_table,
    find_best_linear_approximations,
)

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_hex_or_int(value):
    """Parse a string as hex (0x…) or decimal integer."""
    try:
        if value.startswith("0x") or value.startswith("0X"):
            return int(value, 16)
        return int(value)
    except Exception:
        raise ValueError("Invalid number format. Use integer or hex (0x…).")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


# ── Encrypt / Decrypt (file) ──────────────────────────────────────────────

@app.route("/api/process_file", methods=["POST"])
def process_file():
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    action = request.form.get("action")  # 'encrypt' or 'decrypt'
    try:
        key = parse_hex_or_int(request.form.get("key", "0x0000"))
        iv = parse_hex_or_int(request.form.get("iv", "0x0000"))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    filename = secure_filename(file.filename)
    unique_id = str(uuid.uuid4())
    in_path = os.path.join(app.config["UPLOAD_FOLDER"], f"in_{unique_id}_{filename}")
    file.save(in_path)

    out_filename = f"{action}ed_{filename}"
    out_path = os.path.join(app.config["UPLOAD_FOLDER"], f"out_{unique_id}_{out_filename}")

    try:
        if action == "encrypt":
            encrypt_file(in_path, out_path, key, iv)
        elif action == "decrypt":
            decrypt_file(in_path, out_path, key, iv)
        else:
            return jsonify({"error": "Invalid action"}), 400

        return send_file(out_path, as_attachment=True, download_name=out_filename)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Encrypt / Decrypt (text) ──────────────────────────────────────────────

@app.route("/api/process_text", methods=["POST"])
def process_text():
    data = request.get_json(force=True)
    action = data.get("action")
    text = data.get("text", "")
    try:
        key = parse_hex_or_int(data.get("key", "0x0000"))
        iv = parse_hex_or_int(data.get("iv", "0x0000"))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    try:
        if action == "encrypt":
            plaintext = text.encode("utf-8")
            ct = encrypt_cbc(plaintext, key, iv)
            return jsonify({
                "success": True,
                "result_hex": ct.hex(),
                "result_len": len(ct),
            })
        elif action == "decrypt":
            ct = bytes.fromhex(text)
            pt = decrypt_cbc(ct, key, iv)
            return jsonify({
                "success": True,
                "result_text": pt.decode("utf-8", errors="replace"),
                "result_len": len(pt),
            })
        else:
            return jsonify({"error": "Invalid action"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Brute Force Attack ────────────────────────────────────────────────────

@app.route("/api/brute_force", methods=["POST"])
def run_brute_force():
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    try:
        iv = parse_hex_or_int(request.form.get("iv", "0x0000"))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    known_header_str = request.form.get("known_header", "")
    known_header = known_header_str.encode("utf-8")

    if len(known_header) < 2:
        return jsonify({"error": "Known header must be at least 2 characters."}), 400

    file_bytes = file.read()

    try:
        start = time.time()
        found_key = brute_force_attack(file_bytes, iv, known_header)
        elapsed = time.time() - start

        if found_key is not None:
            # Also try to decrypt a preview
            try:
                preview_bytes = decrypt_cbc(file_bytes, found_key, iv)
                preview = preview_bytes[:200].decode("utf-8", errors="replace")
            except Exception:
                preview = "(binary data)"
            return jsonify({
                "success": True,
                "found_key": f"0x{found_key:04X}",
                "time": f"{elapsed:.3f}",
                "keys_tested": "65,536",
                "preview": preview,
            })
        else:
            return jsonify({
                "success": False,
                "message": "Key not found in the 2^16 search space.",
                "time": f"{elapsed:.3f}",
            })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Cryptanalysis ─────────────────────────────────────────────────────────

@app.route("/api/cryptanalysis", methods=["POST"])
def run_cryptanalysis():
    data = request.get_json(force=True)
    attack_type = data.get("attack_type", "kpa")

    try:
        key = parse_hex_or_int(data.get("key", "0x3A94"))
        iv = parse_hex_or_int(data.get("iv", "0xBEEF"))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    try:
        if attack_type == "kpa":
            return _run_kpa(key, iv)
        elif attack_type == "differential":
            return _run_differential(key)
        elif attack_type == "linear":
            return _run_linear(key)
        elif attack_type == "bitflip":
            return _run_bitflip(key, iv)
        else:
            return jsonify({"error": f"Unknown attack type: {attack_type}"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _run_kpa(key, iv):
    """Known-Plaintext Attack demo."""
    start = time.time()
    pt_block = 0x6F6B
    ct_block = encrypt_block(pt_block, key)

    found_key = None
    keys_tested = 0
    for k in range(0x10000):
        keys_tested += 1
        if encrypt_block(pt_block, k) == ct_block:
            found_key = k
            break

    elapsed = time.time() - start
    return jsonify({
        "success": found_key is not None,
        "attack": "Known-Plaintext Attack (KPA)",
        "known_pt": f"0x{pt_block:04X}",
        "known_ct": f"0x{ct_block:04X}",
        "found_key": f"0x{found_key:04X}" if found_key else None,
        "actual_key": f"0x{key:04X}",
        "keys_tested": f"{keys_tested:,}",
        "time": f"{elapsed:.4f}s",
        "match": found_key == key,
    })


def _run_differential(key):
    """Differential Cryptanalysis demo."""
    start = time.time()
    ddt = build_difference_distribution_table()
    best = find_best_differentials(ddt)
    top5 = [
        {"dx": f"0x{dx:X}", "dy": f"0x{dy:X}", "count": cnt, "prob": f"{prob:.4f}"}
        for dx, dy, cnt, prob in best[:5]
    ]

    # Build DDT as a 2-D list for display
    ddt_display = []
    for dx in range(16):
        row = []
        for dy in range(16):
            row.append(ddt[dx][dy])
        ddt_display.append(row)

    # Run attack with chosen pairs
    best_dx, best_dy, _, best_prob = best[0]
    num_pairs = 32
    key_scores = {}
    for _ in range(num_pairs):
        p1 = random.randint(0, 0xFFFF)
        input_diff = (best_dx << 12) | (best_dx << 4)
        p2 = p1 ^ input_diff
        c1 = encrypt_block(p1, key)
        c2 = encrypt_block(p2, key)

        for k2 in range(0x10000):
            s1 = c1 ^ k2
            s2 = c2 ^ k2
            s1 = shift_rows(s1)
            s2 = shift_rows(s2)
            s1 = nibble_substitution(s1, INV_SBOX)
            s2 = nibble_substitution(s2, INV_SBOX)
            diff = s1 ^ s2
            n0 = (diff >> 12) & 0xF
            n2 = (diff >> 4) & 0xF
            if n0 == best_dy and n2 == best_dy:
                key_scores[k2] = key_scores.get(k2, 0) + 1

    ranked = sorted(key_scores.items(), key=lambda x: x[1], reverse=True)[:5]
    actual_keys = key_expansion(key)
    candidates = [
        {
            "key": f"0x{k:04X}",
            "score": f"{s}/{num_pairs}",
            "correct": k == actual_keys[2],
        }
        for k, s in ranked
    ]

    elapsed = time.time() - start
    return jsonify({
        "success": True,
        "attack": "Differential Cryptanalysis",
        "ddt": ddt_display,
        "top_differentials": top5,
        "best_diff": {"dx": f"0x{best_dx:X}", "dy": f"0x{best_dy:X}", "prob": f"{best_prob:.2f}"},
        "candidates": candidates,
        "actual_k2": f"0x{actual_keys[2]:04X}",
        "time": f"{elapsed:.3f}s",
    })


def _run_linear(key):
    """Linear Cryptanalysis demo."""
    start = time.time()
    lat = build_linear_approximation_table()
    best = find_best_linear_approximations(lat)
    top5 = [
        {"a": f"0x{a:X}", "b": f"0x{b:X}", "bias": f"{bias:+d}", "abs_bias": f"{ab:.4f}"}
        for a, b, bias, ab in best[:5]
    ]

    lat_display = []
    for a in range(16):
        row = []
        for b in range(16):
            row.append(lat[a][b])
        lat_display.append(row)

    best_a, best_b = best[0][0], best[0][1]
    num_pairs = 200
    key_counts = {}
    pairs = [(random.randint(0, 0xFFFF), None) for _ in range(num_pairs)]
    pairs = [(pt, encrypt_block(pt, key)) for pt, _ in pairs]

    for k2 in range(0x10000):
        count = 0
        for pt, ct in pairs:
            state = ct ^ k2
            state = shift_rows(state)
            state = nibble_substitution(state, INV_SBOX)
            pt_n0 = (pt >> 12) & 0xF
            st_n0 = (state >> 12) & 0xF
            lhs = bin(best_a & pt_n0).count("1") % 2
            rhs = bin(best_b & st_n0).count("1") % 2
            if lhs == rhs:
                count += 1
        key_counts[k2] = abs(count - num_pairs // 2)

    ranked = sorted(key_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    actual_keys = key_expansion(key)
    candidates = [
        {
            "key": f"0x{k:04X}",
            "deviation": dev,
            "correct": k == actual_keys[2],
        }
        for k, dev in ranked
    ]

    elapsed = time.time() - start
    return jsonify({
        "success": True,
        "attack": "Linear Cryptanalysis",
        "lat": lat_display,
        "top_approximations": top5,
        "candidates": candidates,
        "actual_k2": f"0x{actual_keys[2]:04X}",
        "time": f"{elapsed:.3f}s",
    })


def _run_bitflip(key, iv):
    """CBC Bit-Flipping Attack demo."""
    original = b"role=user"
    ct = encrypt_cbc(original, key, iv)
    pt_check = decrypt_cbc(ct, key, iv)

    ct_arr = bytearray(ct)
    target_block = 2
    target_byte_in_block = 1
    prev_idx = (target_block - 1) * 2 + target_byte_in_block
    flip_mask = ord("u") ^ ord("r")
    ct_arr[prev_idx] ^= flip_mask

    try:
        modified_pt = decrypt_cbc(bytes(ct_arr), key, iv)
        modified_text = modified_pt.decode("utf-8", errors="replace")
    except Exception:
        modified_text = "(padding error — expected in some cases)"

    return jsonify({
        "success": True,
        "attack": "CBC Bit-Flipping Attack",
        "original_plaintext": original.decode(),
        "original_ct_hex": ct.hex(),
        "flip_position": prev_idx,
        "flip_mask": f"0x{flip_mask:02X}",
        "modified_ct_hex": bytes(ct_arr).hex(),
        "modified_plaintext": modified_text,
        "explanation": (
            "In CBC mode, flipping bit i in ciphertext block C_{n-1} flips "
            "exactly bit i in plaintext block n, but corrupts block n-1. "
            "This lets an attacker modify specific plaintext bytes without "
            "knowing the key."
        ),
    })


# ── Step 4 Attack ─────────────────────────────────────────────────────────

@app.route("/api/step4_attack", methods=["POST"])
def run_step4_attack():
    """Simulate attacking another group's ciphertext."""
    start = time.time()

    # Simulate the other group's encryption
    secret_key = random.randint(0, 0xFFFF)
    iv = 0x1234

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
    known_header = b"FROM: Group"

    # Optimized CBC brute force — only needs 1 block encryption per key
    p0 = (known_header[0] << 8) | known_header[1]
    c0 = (ciphertext[0] << 8) | ciphertext[1]
    expected_input = p0 ^ iv

    candidates = []
    for k in range(0x10000):
        if encrypt_block(expected_input, k) == c0:
            candidates.append(k)

    # Verify with second block
    found_key = None
    if len(known_header) >= 4:
        p1 = (known_header[2] << 8) | known_header[3]
        c1 = (ciphertext[2] << 8) | ciphertext[3]
        for k in candidates:
            if encrypt_block(p1 ^ c0, k) == c1:
                found_key = k
                break
    elif candidates:
        found_key = candidates[0]

    elapsed = time.time() - start

    result = {
        "actual_key": f"0x{secret_key:04X}",
        "iv": f"0x{iv:04X}",
        "ct_preview": ciphertext[:40].hex(),
        "ct_length": len(ciphertext),
        "known_header": known_header.decode(),
        "time": f"{elapsed:.4f}s",
        "keys_tested": "65,536",
    }

    if found_key is not None:
        decrypted = decrypt_cbc(ciphertext, found_key, iv)
        result["success"] = True
        result["found_key"] = f"0x{found_key:04X}"
        result["match"] = found_key == secret_key
        result["decrypted_message"] = decrypted.decode("utf-8", errors="replace")
    else:
        result["success"] = False
        result["message"] = "Key not found."

    return jsonify(result)


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True, port=5000)
