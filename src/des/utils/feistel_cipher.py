from src.utils.encodings_processing import xor_string


def feistel_encrypt(binary_string, keys, encryption_func):
    center = len(binary_string) // 2
    left = binary_string[:center]
    right = binary_string[center:]
    for key in keys:
        left, right = right, xor_string(encryption_func(right, key), left)
    return right + left


def feistel_decrypt(binary_string, keys, encryption_func):
    return feistel_encrypt(binary_string, keys[::-1], encryption_func)
