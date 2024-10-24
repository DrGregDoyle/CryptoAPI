#
#
# def base58check_encode(data):
#     alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
#     num = int.from_bytes(data, 'big') if isinstance(data, bytes) else int(data, 16)
#     encoded = ''
#     while num > 0:
#         num, rem = divmod(num, 58)
#         encoded = alphabet[rem] + encoded
#     padding = 0
#     for byte in data:
#         if byte == 0:
#             padding += 1
#         else:
#             break
#     return '1' * padding + encoded
#
#
# def create_legacy_address(pubkey_hash):
#     versioned_payload = "00" + pubkey_hash  # 0x00 for P2PKH mainnet
#     checksum = h(versioned_payload)[:4]
#     final_payload = versioned_payload + checksum
#     return base58check_encode(final_payload)
#
