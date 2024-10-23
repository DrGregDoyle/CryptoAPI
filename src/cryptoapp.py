from flask import Flask, request, jsonify, render_template

from ecc import secp256k1
from helpers import ascii_to_hex, hash_message
from src.helpers import der_encode

app = Flask(__name__)
curve = secp256k1()


# Serve the homepage
@app.route('/')
def home():
    return render_template('index.html')


@app.route('/generate_private_key', methods=['GET'])
def generate_private_key():
    private_key = str(curve.generate_private_key())
    return jsonify({'private_key': private_key})


@app.route('/get_public_keys', methods=['POST'])
def get_public_keys():
    data = request.get_json()
    private_key = int(data.get('private_key'))

    # Get public keys
    (x, y), cpk = curve.get_public_keys(private_key)

    return jsonify({
        'public_key_x': str(x),
        'public_key_y': str(y),
        'compressed_public_key': cpk
    })


# Endpoint for signing a message
@app.route('/sign_message', methods=['POST'])
def sign():
    data = request.get_json()
    private_key = data.get('private_key')
    message = ascii_to_hex(data.get('message'))

    print(f"DATA MESSAGE: {data.get('message')}")
    print(f"HEX MESSAGE: {message}")

    if not private_key or not message:
        return jsonify({'error': 'Private key and message are required'}), 400

    if isinstance(private_key, str):
        private_key = int(private_key)

    print(f"PRIVATE KEY: {private_key}")
    print(f"TYPE: {type(private_key)}")

    signature = curve.generate_signature(private_key, message)
    print(f"SIGNATURE: {signature}")
    r, s = signature
    der_sig = der_encode(r, s)

    # Cast to str
    return jsonify({
        'r': str(r),
        's': str(s),
        'der': der_sig
    })


# Endpoint for verifying a signature
@app.route('/verify_signature', methods=['POST'])
def verify():
    data = request.get_json()
    message = ascii_to_hex(data.get('message'))
    pubkeyx = int(data.get('public_key_x'))
    pubkeyy = int(data.get('public_key_y'))

    sig_r = int(data.get('r'))
    sig_s = int(data.get('s'))

    public_key = (pubkeyx, pubkeyy)
    signature = (sig_r, sig_s)

    if not public_key or not message or not signature:
        return jsonify({'error': 'Public key, message, and signature are required'}), 400

    is_valid = curve.verify_signature(signature, message, public_key)
    print(f"IS VALID: {is_valid}")
    return jsonify({'is_valid': is_valid})


@app.route('/hash_sha256', methods=['POST'])
def hash_sha256():
    data = request.get_json()
    input_text = data.get('input', '')
    sha256_hash = hash_message(input_text)
    return jsonify({'hash': sha256_hash})


@app.route('/encode_der', methods=['POST'])
def encode_der():
    data = request.get_json()
    r = int(data.get('r', '0'))
    s = int(data.get('s', '0'))

    # Your existing DER encoding function here
    der_encoded = der_encode(r, s)
    return jsonify({'encoded_signature': der_encoded})


if __name__ == '__main__':
    app.run(debug=True)
