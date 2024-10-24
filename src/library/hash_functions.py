"""
Various hashing methods used in Bitcoin
"""
import hashlib
from enum import Enum

from src.library.data_formats import Data


class HashType(Enum):
    SHA256 = "sha256"
    HASH256 = "hash256"
    RIPEMD160 = "ripemd160"
    HASH160 = "hash160"


def hash_function(data: Data, hashtype: HashType) -> str:
    # Get encoded data
    # data = bytes.fromhex(data) if isinstance(data, str) else data

    # Match hashtype | return hex digest
    match hashtype:
        case HashType.SHA256:
            return sha256(data.bytes).hex()
        case HashType.HASH256:
            return hash256(data.bytes).hex()
        case HashType.RIPEMD160:
            return ripemd160(data.bytes).hex()
        case HashType.HASH160:
            return hash160(data.bytes).hex()
        case _:
            raise ValueError("Invalid hash type specified.")


# -- All hash functions are bytes in / bytes out
def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash256(data: bytes) -> bytes:
    return sha256(sha256(data))


def ripemd160(data: bytes) -> bytes:
    r = hashlib.new("ripemd160")
    r.update(data)
    return r.digest()


def hash160(data: bytes) -> bytes:
    return ripemd160(sha256(data))


# Testing
if __name__ == "__main__":
    _data = Data("deadbeef")
    hash1 = hash_function(_data, HashType.SHA256)
    hash2 = hash_function(_data, HashType.HASH256)
    hash3 = hash_function(_data, HashType.HASH160)
    print(f"SHA256(deadbeef) = {hash1}")
    print(f"HASH256(deadbeef) = {hash2}")
    print(f"HASH160(deadbeef) = {hash3}")
    print(_data.to_int())
