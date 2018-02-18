import hashlib
import codecs
import ecdsa as ecdsa
import secrets

from base58 import base58_check_encoding, hasher_sha256
"""
https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
"""

def string_separator():
    print('---------------------------------')


def private_key_to_wif(private_hex_key):
    """
    Encode the private key to btc base58check algorithm.
    :param private_hex_key: random 256 bit private key
    :return: Wallet Import Format key
    """
    private_key = codecs.decode(private_hex_key, "hex_codec")
    return base58_check_encoding(private_key, version=128)


def private_key_to_public_key(private_key):
    """
    Generates a 512-bit public key from the private key using Elliptic Curve
    Digital Signature Algorithm.
    :param private_key: private_key
    :return: 512 bit public key with 04 prefix (bytes string)
    """
    sk = ecdsa.SigningKey.from_string(codecs.decode(private_key, "hex_codec"),
                                      curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()

    # Bitcoin protocol adds a prefix of 04 to the public key
    return b'04' + codecs.encode(vk.to_string(), "hex_codec")


def public_key_512bit_to_hash_public_key_160bit(public_key):
    """
    Generate a 160 bit public key hash.
    :param public_key: public_key 512 bit with prefix.
    :return: 160 bit public key hash.
    """
    assert isinstance(public_key, bytes)

    r = hasher_sha256(codecs.decode(public_key, "hex_codec"))

    hasher = hashlib.new('ripemd160')
    hasher.update(r)
    r = hasher.digest()

    return r


def encode_to_btc_addr(hash):
    """
    Convert hash to Pay-to-PubkeyHash (P2PKH) address.
    :param hash: hash to convert
    :return: 1 + base58check(hash)
    """
    # Since '1' is a zero byte, it won't be present in the output address.
    return '1' + base58_check_encoding(hash, version=0)


def private_key_to_btc_public_key(private_key):
    """
    Generate BTC address from a 256 bit private key.
    :param private_key:
    :return:
    """
    return encode_to_btc_addr(
        public_key_512bit_to_hash_public_key_160bit(
            private_key_to_public_key(private_key)))


# private_key = secrets.token_hex(32)  # nBytes - 32 Bytes = 256 Bits - 2^256 pos
# print("Random 256 bits Private Key: " + private_key)  # 256/4 = 64 char in Hexa, 2 char per byte
# string_separator()
#
# print("WIF Private Key: " + private_key_to_wif(private_key))
# string_separator()
#
# pub_key512bit = private_key_to_public_key(private_key)
# print("512 bit public key with prefix: " + str(pub_key512bit))
# string_separator()
#
# pub_key160bit = public_key_512bit_to_hash_public_key_160bit(pub_key512bit)
# print("160 bit public key hash: " + str(pub_key160bit))
# string_separator()
#
# print("BTC Address: " + encode_to_btc_addr(pub_key160bit))
