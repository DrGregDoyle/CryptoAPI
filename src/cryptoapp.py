from flask import Flask, render_template, jsonify, request

from src.library.address import LockType, get_address_prefix
from src.library.codec import der_decode, encode_base58check, encode_bech32
from src.library.codec import der_encode, decompress_public_key
from src.library.curves import CurveType, get_curve
from src.library.data_formats import Data
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
    message = Data(data.get('message'))

    if not private_key or not message:
        return jsonify({'error': 'Private key and message are required'}), 400

    signature = generate_signature(private_key, message.hex, curve_type)

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
    message = Data(data.get('message'))
    cpk = data.get('cpk')
    sig_r = data.get('r')
    sig_s = data.get('s')
    der_encoded_sig = data.get('der_sig')

    if (sig_r == "" or sig_s == "") and der_encoded_sig != "":
        r, s = der_decode(der_encoded_sig)
    elif sig_r != "" and sig_s != "":
        r, s = int(sig_r), int(sig_s)
    else:
        raise ValueError(f"Missing one or more fields.")

    public_key = decompress_public_key(cpk, curve_type)
    signature = (r, s)

    if not public_key or not message or not signature:
        return jsonify({'error': 'Public key, message, and signature are required'}), 400

    is_valid = verify_signature(signature, message.hex, public_key, curve_type)
    print(f"IS VALID: {is_valid}")
    return jsonify({'is_valid': is_valid})


@app.route('/hash', methods=['POST'])
def hash_sha256():
    # Get input as hex string
    data = request.get_json()
    input_text = Data(data.get('input'))

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


@app.route('/encode_der', methods=['POST'])
def encode_der():
    data = request.get_json()
    r = int(data.get('r', '0'))
    s = int(data.get('s', '0'))

    # Your existing DER encoding function here
    der_encoded = der_encode(r, s)
    return jsonify({'encoded_signature': der_encoded})


@app.route('/decode_der', methods=['POST'])
def decode_der():
    data = request.get_json()
    der_string = data.get('der_encoded_signature')

    # Decode DER string
    decoded_sig = der_decode(der_string)
    r, s = decoded_sig
    return jsonify({
        "r": str(r),
        "s": str(s)
    })


@app.route('/pubkeyhash', methods=['POST'])
def hash_compressed_public_key():
    data = request.get_json()
    cpk = data.get('compressed_public_key')

    cpk_data = Data(cpk)

    pubkeyhash = hash_function(cpk_data, HashType.HASH160)
    return jsonify({'pubkeyhash': pubkeyhash})


@app.route('/generate_bitcoin_address', methods=['POST'])
def generate_bitcoin_address():
    data = request.get_json()  # Data comes from generateBitcoinAddress() = {address-type, pubkey-hash}
    address_type = data.get('address_type', 'legacy')
    pubkey_hash = data.get('pub_key_hash')

    print(data)

    if not pubkey_hash:
        return jsonify({'error': 'Public key hash required.'}), 400

    if address_type == "legacy":
        address_prefix = get_address_prefix(LockType.P2PKH)
        pubkey_data = Data(address_prefix + pubkey_hash)
        address = encode_base58check(pubkey_data)
    else:
        address = encode_bech32(Data(pubkey_hash))

    return jsonify({'bitcoin_address': address})


if __name__ == '__main__':
    app.run(debug=True)
