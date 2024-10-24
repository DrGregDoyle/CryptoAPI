from flask import Flask, render_template, jsonify, request

from src.library.codec import der_encode
from src.library.curves import CurveType, get_curve
from src.library.data_formats import ascii_to_hex
from src.library.ecc_keys import KeyPair
from src.library.ecdsa import generate_signature, verify_signature
from src.library.hash_functions import HashType, hash_function

app = Flask(__name__)
curve_type = CurveType.SECP256K1  # TODO: Enable multiple types
curve = get_curve(curve_type)


# Serve the homepage
@app.route('/')
def home():
    return render_template('index.html')


@app.route('/generate_private_key', methods=['GET'])
def generate_private_key():
    private_key = KeyPair.generate_private_key(curve)
    return jsonify({'private_key': str(private_key)})


@app.route('/get_public_keys', methods=['POST'])
def get_public_keys():
    data = request.get_json()
    private_key = int(data.get('private_key'))

    # Get Public Keys
    kp = KeyPair(private_key=private_key, curve_type=curve_type)
    x, y = kp.public_key_point
    cpk = kp.compressed_public_key

    return jsonify({
        'public_key_x': str(x),
        'public_key_y': str(y),
        'compressed_public_key': cpk
    })


# Endpoint for signing a message
@app.route('/sign_message', methods=['POST'])
def sign():
    data = request.get_json()
    private_key = int(data.get('private_key'))
    message = ascii_to_hex(data.get('message'))

    if not private_key or not message:
        return jsonify({'error': 'Private key and message are required'}), 400

    signature = generate_signature(private_key, message, curve_type)

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
    cpk = data.get('cpk')

    # pubkeyx = int(data.get('public_key_x'))
    # pubkeyy = int(data.get('public_key_y'))

    sig_r = int(data.get('r'))
    sig_s = int(data.get('s'))

    public_key = curve.decompress_point(cpk)
    signature = (sig_r, sig_s)

    if not public_key or not message or not signature:
        return jsonify({'error': 'Public key, message, and signature are required'}), 400

    is_valid = verify_signature(signature, message, public_key, curve_type)
    print(f"IS VALID: {is_valid}")
    return jsonify({'is_valid': is_valid})


@app.route('/hash', methods=['POST'])
def hash_sha256():
    # Get input as hex string
    data = request.get_json()
    input_text = ascii_to_hex(data.get('input'))

    # Run all hash functions
    sha256_hash = hash_function(input_text, HashType.SHA256)
    hash256_hash = hash_function(input_text, HashType.HASH256)
    ripemd160_hash = hash_function(input_text, HashType.RIPEMD160)
    hash160_hash = hash_function(input_text, HashType.HASH160)

    return jsonify({
        'sha256': sha256_hash,
        'hash256': hash256_hash,
        'ripemd160': ripemd160_hash,
        'hash160': hash160_hash
    })


#
#
# @app.route('/encode_der', methods=['POST'])
# def encode_der():
#     data = request.get_json()
#     r = int(data.get('r', '0'))
#     s = int(data.get('s', '0'))
#
#     # Your existing DER encoding function here
#     der_encoded = der_encode(r, s)
#     return jsonify({'encoded_signature': der_encoded})
#
#
# @app.route('/generate_bitcoin_address', methods=['POST'])
# def generate_bitcoin_address():
#     data = request.get_json()
#
#     # Determine if input is a compressed public key or x, y coordinates
#     compressed_pubkey = data.get('compressed_public_key')
#     pubkey_x = data.get('public_key_x')
#     pubkey_y = data.get('public_key_y')
#     address_type = data.get('address_type', 'legacy')
#
#     if compressed_pubkey:
#         pass
#         # pubkey_bytes = bytes.fromhex(compressed_pubkey)
#     elif pubkey_x and pubkey_y:
#         # Compress the public key from x and y coordinates
#         compressed_pubkey = curve.compress_point((int(pubkey_x), int(pubkey_y)))
#     else:
#         return jsonify({'error': 'Invalid input'}), 400
#
#     # Hash the public key for address generation
#     sha256_hash = hash_message(compressed_pubkey)
#     pubkey_hash = ripemd_message(sha256_hash)
#
#     if address_type == 'legacy':
#         bitcoin_address = create_legacy_address(pubkey_hash)
#     elif address_type == 'bech32':
#         bitcoin_address = create_bech32_address(pubkey_hash)
#     else:
#         return jsonify({'error': 'Invalid address type'}), 400
#
#     return jsonify({'bitcoin_address': bitcoin_address})


if __name__ == '__main__':
    app.run(debug=True)
