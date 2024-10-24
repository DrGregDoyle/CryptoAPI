"""
Helper Functions
"""


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
