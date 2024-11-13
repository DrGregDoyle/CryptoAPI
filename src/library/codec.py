"""
Encoding/Decoding methods
"""

from src.library.bech32 import convertbits, bech32_encode, Encoding, bech32_decode
from src.library.curves import CurveType, get_curve
from src.library.data_formats import Data
from src.library.hash_functions import checksum, HashType


# --- PUBLIC KEY COMPRESSION/EXTRACTION --- #

def compress_public_key(pubkey_point: tuple):
    x, y = pubkey_point
    prefix = "02" if y % 2 == 0 else "03"
    bit_length = (x.bit_length() + 3) // 4
    return prefix + format(x, f"0{bit_length}x")


def decompress_public_key(cpk: str, curve_type: CurveType = CurveType.SECP256K1):
    # Strip leading "0x" if it exists
    if cpk.startswith("0x"):
        cpk = cpk[2:]

    # Break up into parity and x coordinate
    parity = int(cpk[:2], 16)
    x = int(cpk[2:], 16)

    # Verify x is on the curve
    curve = get_curve(curve_type)
    if not curve.is_x_on_curve(x):
        raise ValueError(f"Decoded x value {hex(x)} not found on curve type: {curve_type}")

    # Get possible y value
    temp_y = curve.find_y_from_x(x)

    # Select the correct y-coordinate based on parity
    y = temp_y if temp_y % 2 == parity else curve.p - temp_y

    # Verify point is on the curve
    if not curve.is_point_on_curve((x, y)):
        raise ValueError(f"Point {(hex(x), hex(y))} not found on curve type: {curve_type}")

    # Return point
    return x, y


# --- BASE 58 CODEC --- #
base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def encode_base58(data: Data) -> str:
    # Get number of leading zeros
    zero_bytes = 0
    for i in range(len(data.bytes)):
        chunk = data.bytes[i:i + 1]
        if chunk == b'\x00':
            zero_bytes += 1

    # Get int value of data
    num = data.int

    # Encode
    encoded_string = ""
    while num > 0:
        num, res = divmod(num, 58)  # Returns (num//58, num % 58)
        encoded_string = base58_alphabet[res] + encoded_string

    # Add leading zeros
    encoded_string = "1" * zero_bytes + encoded_string
    return encoded_string


def decode_base58(encoded_string: str) -> Data:
    # Create an integer to hold the result
    total = 0

    # Reverse string for ease of use
    reverse_encoded_string = "".join([encoded_string[i] for i in range(len(encoded_string) - 1, -1, -1)])

    for i in range(len(reverse_encoded_string)):
        _num = base58_alphabet.index(reverse_encoded_string[i])
        total += pow(58, i) * _num

    return Data(total)


def encode_base58check(data: Data) -> str:
    """
    We add a hash256-checksum to the data before base58 encoding
    """
    _checksum = checksum(data, hashtype=HashType.HASH256, byte_num=4)
    return encode_base58(data + _checksum)


def decode_base58check(encoded_string: str) -> Data:
    decoded_data = decode_base58(encoded_string)

    # Confirm checksum
    _data, _checksum = decoded_data.bytes[:-4], decoded_data.bytes[-4:]
    data = Data(_data)
    if checksum(data) != _checksum:
        raise ValueError("Base58Check encoded data checksum verification failed")

    return decoded_data


# --- BECH32 ENCODING --- #
def encode_bech32(data: Data):
    """
    Encoding is fixed to BECH32 as we only generate addresses for pubkeyhash. When moving to segwit V1 we need Bech32M.
    """
    # Extract the bytes from the Data instance
    pubkey_hash = data.bytes

    # Ensure pubkey_hash is exactly 20 bytes
    if len(pubkey_hash) != 20:
        raise ValueError("P2WPKH pubkey hash must be exactly 20 bytes.")

    # Convert 8-bit data to 5-bit using the reference convertbits function
    converted_data = convertbits(pubkey_hash, 8, 5, pad=False)
    if converted_data is None:
        raise ValueError("Failed to convert data from 8-bit to 5-bit.")

    # Prepend version byte (0x00 for SegWit v0)
    converted_data = [0] + converted_data

    # Submit converted_data using "bc" as hrp
    bech32_address = bech32_encode(hrp="bc", data=converted_data, spec=Encoding.BECH32)

    # Decode to verify checksum
    hrp, decoded_data, spec = bech32_decode(bech32_address)
    if hrp != 'bc' or decoded_data is None:
        raise ValueError("Checksum verification failed.")
    return bech32_address


# --- DER CODEC --- #

def der_encode(r: int, s: int):
    """
    Given an r and s value from ECDSA, we return a DER encoded signature.

    via Pieter Wuille:
        A correct DER-encoded signature has the following form:

        0x30: a header byte indicating a compound structure.
        A 1-byte length descriptor for all what follows.
        0x02: a header byte indicating an integer.
        A 1-byte length descriptor for the R value
        The R coordinate, as a big-endian integer.
        0x02: a header byte indicating an integer.
        A 1-byte length descriptor for the S value.
        The S coordinate, as a big-endian integer.
    """

    def der_encode_integer(value: int) -> bytes:
        """Encodes an integer according to DER format with a 0x02 header."""
        # Convert to big-endian bytes
        value_bytes = value.to_bytes((value.bit_length() + 7) // 8, byteorder='big')

        # Ensure it is unsigned by prepending a 0x00 byte if the high bit is set
        if value_bytes[0] & 0x80:
            value_bytes = b'\x00' + value_bytes

        # Add the integer header and length byte
        return b'\x02' + len(value_bytes).to_bytes(1, byteorder='big') + value_bytes

    # Encode r and s
    byte_encoded_r = der_encode_integer(r)
    byte_encoded_s = der_encode_integer(s)

    # Combine r and s, and add the compound structure header
    der_content = byte_encoded_r + byte_encoded_s
    der_bytes = b'\x30' + len(der_content).to_bytes(1, byteorder='big') + der_content

    return der_bytes.hex()


def der_decode(encoded_signature: str):
    # We proceed by hex chunks
    confirm_byte = encoded_signature[:2]
    # sig_length = encoded_signature[2:4]

    # r
    r_int_confirm = encoded_signature[4:6]
    r_length = encoded_signature[6:8]
    r = encoded_signature[8:8 + int(r_length, 16) * 2]  # Length is in bytes. Multiply by 2 for hex chars.

    # s
    _index = 8 + int(r_length, 16) * 2
    s_int_confirm = encoded_signature[_index: _index + 2]
    s_length = encoded_signature[_index + 2:_index + 4]
    s = encoded_signature[_index + 4: _index + 4 + 2 * int(s_length, 16)]

    # Confirmation
    if confirm_byte != "30":
        raise ValueError(f"Did not get expected confirm byte. Expected '30', received: {confirm_byte}")
    if r_int_confirm != "02":
        raise ValueError(f"Did not get expected r int type confirmation. Expected '02', received {r_int_confirm}")
    if s_int_confirm != "02":
        raise ValueError(f"Did not get expected s int type confirmation. Expected '02', received {s_int_confirm}")

    return int(r, 16), int(s, 16)


if __name__ == "__main__":
    _data = Data("5fe59c4a885ecd5358843a92a16854d9eb891ac4")
    _address = encode_bech32(_data)

    print(_address)
