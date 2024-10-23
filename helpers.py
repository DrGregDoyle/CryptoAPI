"""
Helper Functions
"""
import re

def ascii_to_hex(text: str):
    """
    If text is not a hex string, turns all characters into ascii integer values and returns the correspondhing
    hex string.
    """
    pattern = r'^(0x)?[0-9a-fA-F]+$'
    is_hex =  bool(re.match(pattern, text))
    if is_hex:
        return text
    else:
        return text.encode().hex()