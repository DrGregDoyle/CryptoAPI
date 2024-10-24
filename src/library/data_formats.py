"""
Classes and methods to handle data types
"""
import re


def get_bytes(data: str | bytes) -> bytes:
    """
    Given a data blob, we return the associated byte value.
    """
    return bytes.fromhex(data) if isinstance(data, str) else data


def get_hex(data: str | bytes) -> str:
    """
    Given a data blob, we return the associated hex value.
    """
    return data.hex() if isinstance(data, bytes) else data


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
