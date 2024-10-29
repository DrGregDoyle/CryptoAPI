"""
Methods for generating an Address
"""


class LockType:
    P2PKH = "p2pkh"
    P2SH = "p2sh"
    P2WPKH = "p2wpkh"
    P2WSH = "p2wsh"


def get_address_prefix(address_type: LockType = LockType.P2PKH, mainnet: bool = True):
    match address_type:
        case LockType.P2PKH:
            return "00" if mainnet else "6f"
        case LockType.P2SH:
            return "05" if mainnet else "C4"
        case _:
            raise ValueError("Incorrect LockType chosen")

# def generate_bitcoin_address(public_key: str | tuple):
#     # Generate compressed public_key
#     pubkey =
