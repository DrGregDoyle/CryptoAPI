"""
Encoding/Decoding methods
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
