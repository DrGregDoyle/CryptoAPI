from flask import Flask, request, jsonify, render_template
from ecc import secp256k1
from helpers import ascii_to_hex

app = Flask(__name__)
curve = secp256k1()

# Serve the homepage
@app.route('/')
def home():
    return render_template('index.html')

# Endpoint for key generation
@app.route('/generate_keys', methods=['GET'])
def generate_keys():
    private_key, (x, y) = curve.generate_keys()
    compressed_key = curve.compress_point((x, y))

    print(f"PRIVATE KEY: {private_key}")
    print(f"PUBKEYPT: {(x,y)}")

    # Cast to str
    privkey = str(private_key)
    pubkeyx = str(x)
    pubkeyy = str(y)

    return jsonify({
        'private_key': privkey,
        'public_key_point': (pubkeyx,pubkeyy),
        'compressed_public_key': compressed_key
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
    r,s = signature

    #Cast to str
    return jsonify({'r': str(r), 's': str(s)})


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


if __name__ == '__main__':
    app.run(debug=True)
