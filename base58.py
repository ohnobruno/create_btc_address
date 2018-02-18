import hashlib

base58_alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def base58encode(n: int):
    """
    Encode n in a base58-encoded string
    :param n: integer to be encoded
    :return: n base58 encoded
    """
    result = ''
    while n > 0:
        result = base58_alphabet[n % 58] + result
        n //= 58
    return result


def _count_leading_chars(string, char):
    leading_char = 0
    for c in string:
        if c == char:
            leading_char += 1
        else:
            break
    return leading_char


def hasher_sha256(src):
    hasher = hashlib.sha256()
    hasher.update(src)
    return hasher.digest()


def base58_check_encoding(payload, version=0):
    """
    Base 58 binary-to-text encoding used for encoding Bitcoin addresses.
    https://en.bitcoin.it/wiki/Base58Check_encoding
    :param payload: Data to be converted.
    :param version: One byte of version/application information.
                    BTC pubkey hash addresses use the version 0.
    :return: A base58-encoded string.
    """
    assert isinstance(payload, bytes)

    # 1. Take the version byte and payload bytes,
    # and concatenate them together (bytewise)
    version_payload = bytes([version]) + payload

    # 2. Take the first four bytes of SHA256(SHA256(results of step 1))
    first_sha256 = hasher_sha256(version_payload)
    second_sha256 = hasher_sha256(first_sha256)
    checksum = second_sha256[:4]

    # 3. Concatenate the results of step 1 and the results
    # of step 2 together (bytewise)
    # 4. The result should be normalized to not have any
    # leading base-58 zeroes (character '1').
    s = version_payload + checksum

    # 5. Each leading zero byte shall be represented by its own character '1'
    # in the final result.
    leading_zeros = _count_leading_chars(s, '0')

    # 6. Concatenate the 1's from step 5 with the results of step 4:
    return '1' * leading_zeros + base58encode(int.from_bytes(s, 'big'))
