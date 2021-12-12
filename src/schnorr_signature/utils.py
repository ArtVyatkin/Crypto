from bitarray import bitarray

from src.sha256.main import sha256
from src.utils.encodings_processing import binary_to_hex


def int2sha_bin(number):
    return sha256(bitarray(bin(number)[2:]).to01())


def bin_str2int(bin_str):
    return int(bin_str, 2)


def int2hex_str(number):
    return binary_to_hex(bin(number)[2:])
