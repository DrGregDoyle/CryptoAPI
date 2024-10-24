"""
Class to handle data. The default value will be byte-encoded data.
"""
import re
from typing import Literal


class Data:
    def __init__(self, data: str | bytes | int, byte_order: Literal["big", "little"] = "big"):
        """
        Initialize the Data object, handling integers, ASCII, hexadecimal strings, and bytes.
        """
        # Byte order for changing between int and bytes
        self.byte_order = byte_order

        if isinstance(data, bytes):
            self._data = data
        elif isinstance(data, int):
            bit_length = (data.bit_length() + 7) // 8
            self._data = data.to_bytes(bit_length, self.byte_order)
        elif isinstance(data, str):
            if self.is_hex(data):
                self._data = bytes.fromhex(data)
            else:
                self._data = data.encode()
        else:
            raise TypeError("Input must be a bytes object, integer, hexadecimal string, or ASCII string.")

    @property
    def bytes(self) -> bytes:
        return self._data

    @property
    def hex(self) -> str:
        return self._data.hex()

    @property
    def int(self):
        return int.from_bytes(self._data, self.byte_order)

    @staticmethod
    def is_hex(text: str) -> bool:
        """
        Return True if the string is in hexadecimal format, otherwise return False.
        """
        hex_pattern = r'^(0x)?[0-9a-fA-F]+$'
        return bool(re.match(hex_pattern, text))
