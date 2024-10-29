"""
Methods for public and private keys
"""
from secrets import randbits

from src.library.codec import compress_public_key
from src.library.curves import CurveType, get_curve
from src.library.ecc import EllipticCurve


class KeyPair:
    """
    A class for a private and public keypair for use in elliptic curve cryptography
    """

    def __init__(self, private_key: int | None = None, curve_type: CurveType = CurveType.SECP256K1):
        self.curve = get_curve(curve_type)
        self.private_key = private_key if private_key else self.generate_private_key(self.curve)
        self.public_key_point = self.curve.multiply_generator(self.private_key)
        self.compressed_public_key = compress_public_key(self.public_key_point)

    @staticmethod
    def generate_private_key(curve: EllipticCurve):
        """
        Generates a random, non-zero, cryptographically secure private key for use in elliptic curve cryptography.
        """
        return next(x for x in (randbits(curve.p.bit_length()) % curve.order for _ in iter(int, 1)) if x != 0)
