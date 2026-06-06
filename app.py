import os
import uuid
from flask import Flask, request, jsonify, render_template, send_file
from werkzeug.utils import secure_filename
from cbc_mode import encrypt_file, decrypt_file
from brute_force import brute_force_attack

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def parse_hex_or_int(value):
    try:
        if value.startswith('0x') or value.startswith('0X'):
            return int(value, 16)
        return int(value)
    except Exception:
        raise ValueError("Invalid number format. Use integer or hex (0x...).")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/process_file', methods=['POST'])
def process_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    action = request.form.get('action') # 'encrypt' or 'decrypt'
    try:
        key = parse_hex_or_int(request.form.get('key', '0x0000'))
        iv = parse_hex_or_int(request.form.get('iv', '0x0000'))
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    filename = secure_filename(file.filename)
    unique_id = str(uuid.uuid4())
    in_filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"in_{unique_id}_{filename}")
    file.save(in_filepath)

    out_filename = f"{action}ed_{filename}"
    out_filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"out_{unique_id}_{out_filename}")

    try:
        if action == 'encrypt':
            encrypt_file(in_filepath, out_filepath, key, iv)
        elif action == 'decrypt':
            decrypt_file(in_filepath, out_filepath, key, iv)
        else:
            return jsonify({'error': 'Invalid action'}), 400
            
        return send_file(out_filepath, as_attachment=True, download_name=out_filename)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/brute_force', methods=['POST'])
def run_brute_force():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    try:
        iv = parse_hex_or_int(request.form.get('iv', '0x0000'))
        known_header_str = request.form.get('known_header', '')
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    # Parse header string to bytes. E.g. "BM" or "Dear Students,"
    # If the user typed \x..., we should handle it or just treat as string
    known_header = known_header_str.encode('utf-8') 
    # if empty, maybe try BM for bmp? But better require it.

    file_bytes = file.read()
    
    try:
        found_key = brute_force_attack(file_bytes, iv, known_header)
        if found_key is not None:
            return jsonify({'success': True, 'found_key': f"0x{found_key:04X}"})
        else:
            return jsonify({'success': False, 'message': 'Key not found in the search space.'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
