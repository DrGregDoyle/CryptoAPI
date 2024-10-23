"""
Helper Functions
"""
import re
from hashlib import sha256


def is_hex(text: str) -> bool:
    """
    Returns TRUE if string is all in hexadecimal, otherwise returns False.
    """
    hex_pattern = r'^(0x)?[0-9a-fA-F]+$'
    return bool(re.match(hex_pattern, text))


def ascii_to_hex(text: str):
    """
    If text is not a hex string, turns all characters into ascii integer values and returns the correspondhing
    hex string.
    """
    return text if is_hex(text) else text.encode().hex()


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
    # Headers
    cs_header = bytes.fromhex("30")
    int_header = bytes.fromhex("02")

    # Format r
    hex_r = r.to_bytes(length=32, byteorder="big").hex()
    binary_r = format(r, "0256b")  # 256 bits
    if binary_r[0] == "1":
        # Signed int - prepend byte
        hex_r = "00" + hex_r
    byte_r = bytes.fromhex(hex_r)
    byte_encoded_r = int_header + len(byte_r).to_bytes(length=1, byteorder="big") + byte_r

    # Format s
    hex_s = s.to_bytes(length=32, byteorder="big").hex()
    binary_s = format(s, "0256b")
    if binary_s[0] == "1":
        hex_s = "00" + hex_s
    byte_s = bytes.fromhex(hex_s)
    byte_encoded_s = int_header + len(byte_s).to_bytes(length=1, byteorder="big") + byte_s

    # Format DER
    der_length = len(byte_encoded_r + byte_encoded_s)  # Byte length

    der_bytes = cs_header + der_length.to_bytes(length=1, byteorder="big") + byte_encoded_r + byte_encoded_s
    return der_bytes.hex()


def hash_message(text: str):
    """
    Given a string, we return the SHA256 hex digest of the corresponding hexadecimal value of the given string.
    """
    # Get message as hex string
    message = ascii_to_hex(text) if not is_hex(text) else text

    # SHA256
    return sha256(message.encode()).hexdigest()


def double_hash(text: str):
    # Get message as hex string
    message = ascii_to_hex(text) if not is_hex(text) else text

    return hash_message(hash_message(text))
