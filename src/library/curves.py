"""
NIST Elliptic Curves - See https://www.secg.org/sec2-v2.pdf for constants.
All groups of rational points have prime order, hence all curves are suitable for use in ECDSA.
"""

from enum import Enum

from src.library.ecc import EllipticCurve


class CurveType(Enum):
    SECP192R1 = "secp192r1"
    SECP192K1 = "secp192k1"
    SECP224K1 = "secp224k1"
    SECP224R1 = "secp224r1"
    SECP256K1 = "secp256k1"
    SECP256R1 = "secp256r1"
    SECP384R1 = "secp384r1"
    SECP521R1 = "secp521r1"


def get_curve(curve_type: CurveType):
    func_map = {
        CurveType.SECP256K1: secp256k1,
        CurveType.SECP192K1: secp192k1,
        CurveType.SECP224K1: secp224k1,
        CurveType.SECP192R1: secp192r1,
        CurveType.SECP224R1: secp224r1,
        CurveType.SECP256R1: secp256r1,
        CurveType.SECP384R1: secp384r1,
        CurveType.SECP521R1: secp521r1
    }
    try:
        return func_map[curve_type]()
    except KeyError:
        raise ValueError(f"Invalid curve specified: {curve_type}")


def secp192k1():
    # Constants
    a = 0x0
    b = 0x3
    p = pow(2, 192) - pow(2, 32) - pow(2, 12) - pow(2, 8) - pow(2, 7) - pow(2, 6) - pow(2, 3) - 1
    order = 0xfffffffffffffffffffffffe26f2fc170f69466a74defd8d
    generator = (0xdb4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d, 0x9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d)

    # Return curve object
    return EllipticCurve(a, b, p, order, generator)


def secp192r1():
    # Constants
    a = 0xfffffffffffffffffffffffffffffffefffffffffffffffc
    b = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
    p = pow(2, 192) - pow(2, 64) - 1
    order = 0xffffffffffffffffffffffff99def836146bc9b1b4d22831
    generator = (0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012, 0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811)

    # Return curve object
    return EllipticCurve(a, b, p, order, generator)


def secp224k1():
    # Constants
    a = 0x0
    b = 0x5
    p = pow(2, 224) - pow(2, 32) - pow(2, 12) - pow(2, 11) - pow(2, 9) - pow(2, 7) - pow(2, 4) - pow(2, 1) - 1
    order = 0x010000000000000000000000000001dce8d2ec6184caf0a971769fb1f7
    generator = (
        0xa1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c,
        0x7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5)

    # Return curve object
    return EllipticCurve(a, b, p, order, generator)


def secp224r1():
    # Constants
    a = 0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe
    b = 0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4
    p = pow(2, 224) - pow(2, 96) + 1
    order = 0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d
    generator = (
        0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21,
        0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34)

    # Return curve object
    return EllipticCurve(a, b, p, order, generator)


def secp256k1():
    # Constants
    a = 0
    b = 7
    p = pow(2, 256) - pow(2, 32) - pow(2, 9) - pow(2, 8) - pow(2, 7) - pow(2, 6) - pow(2, 4) - 1
    order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
    generator = (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
                 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)

    # Return curve object
    return EllipticCurve(a, b, p, order, generator)


def secp256r1():
    # Constants
    a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
    b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    p = pow(2, 224) * (pow(2, 32) - 1) + pow(2, 192) + pow(2, 96) - 1
    order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    generator = (
        0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
        0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

    # Return curve object
    return EllipticCurve(a, b, p, order, generator)


def secp384r1():
    # Constants
    a = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc
    b = 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef
    p = pow(2, 384) - pow(2, 128) - pow(2, 96) + pow(2, 32) - 1
    order = 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973
    generator = (
        0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
        0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f)

    # Return curve object
    return EllipticCurve(a, b, p, order, generator)


def secp521r1():
    # Constants
    a = 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc
    b = 0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00
    p = pow(2, 521) - 1  # 13th Mersenne prime
    order = 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409
    generator = (
        0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66,
        0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650)

    # Return curve object
    return EllipticCurve(a, b, p, order, generator)
