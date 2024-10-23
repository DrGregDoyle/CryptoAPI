from src.helpers import double_hash


def base58check_encode(data):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = int.from_bytes(data, 'big') if isinstance(data, bytes) else int(data, 16)
    encoded = ''
    while num > 0:
        num, rem = divmod(num, 58)
        encoded = alphabet[rem] + encoded
    padding = 0
    for byte in data:
        if byte == 0:
            padding += 1
        else:
            break
    return '1' * padding + encoded


def bech32_encode(hrp, data):
    CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])


def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("Invalid padding")
    return ret


def bech32_create_checksum(hrp, data):
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    values = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp] + data + [0, 0, 0, 0, 0, 0]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= generator[i] if (top >> i) & 1 else 0
    return [(chk >> 5 * (5 - i)) & 31 for i in range(6)]


def create_legacy_address(pubkey_hash):
    versioned_payload = "00" + pubkey_hash  # 0x00 for P2PKH mainnet
    checksum = double_hash(versioned_payload)[:4]
    final_payload = versioned_payload + checksum
    return base58check_encode(final_payload)


def create_bech32_address(pubkey_hash):
    data = [0] + convertbits(pubkey_hash, 8, 5)
    return bech32_encode('bc', data)
