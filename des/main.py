from typing import Tuple

from des.config import (
    APPENDED_LETTER,
    IP_PERMUTATION,
    EXTENSION_TABLE,
    BASIC_CONVERSION_TABLES,
    FINAL_DES_FUNCTION_PERMUTATION,
    REVERSE_IP_PERMUTATION,
    INITIAL_KEY_PERMUTATION,
    ROUND_KEYS_SHIFTS,
    FINAL_KEY_PERMUTATION
)


def to_binary_str(string, length=8):
    return f"{string:0{length}b}"


def to_binary(text):
    return "".join([to_binary_str(ord(letter)) for letter in text])


def chunk_str(text, chunk_length, appended_letter=None):
    if appended_letter is not None:
        number_of_last_letters = len(text) % chunk_length
        if number_of_last_letters != 0:
            text += appended_letter * (chunk_length - number_of_last_letters)
    return [text[i: i + chunk_length] for i in range(0, len(text), chunk_length)]


def from_binary(binary_text, appended_letter=None):
    return "".join(
        [chr(int(chunk, 2)) for chunk in chunk_str(binary_text, 8) if
         appended_letter is None or chunk != to_binary_str(ord(appended_letter))]
    )


# Permutation length can be different from the length of the string.
def permute(string, permutation: Tuple, bias=-1):
    return "".join([string[i + bias] for i in permutation])


def add_parity_bits(binary_string, calculate_bit=lambda last_bits: "0"):
    result = []
    for i in range(0, len(binary_string), 7):
        chunk = binary_string[i: i + 7]
        result += binary_string[i: i + 7] + calculate_bit(chunk)
    return ''.join(result)


def get_round_keys(binary_key, initial_key_permutation, round_keys_shifts, final_key_permutation):
    # permuted_key = permute(binary_key, initial_key_permutation, -1)
    # ---------------------------------------------------------------
    round_keys = []
    key_with_parity_bits = add_parity_bits(binary_key)
    permuted_key = permute(key_with_parity_bits, initial_key_permutation, -1)

    center_index = len(permuted_key) // 2
    c = permuted_key[:center_index]
    d = permuted_key[center_index:]
    for shift_value in round_keys_shifts:
        c = shift_string(c, shift_value)
        d = shift_string(d, shift_value)
        round_keys.append(permute(c + d, final_key_permutation))
    return round_keys


# left shift on 1 item: [1, 2, 3, 4] -> [2, 3, 4, 1]
def shift_string(string, shift_value, is_left_shift=True):
    shift_value = shift_value * (1 if is_left_shift else -1)
    return string[shift_value:] + string[:shift_value]


# leaves leading zeros
def xor_string(first_str, second_str):
    result_len = max(len(first_str), len(second_str))
    return f"{(int(first_str, 2) ^ int(second_str, 2)):0{result_len}b}"


def feistel_encrypt(binary_string, keys, encryption_func):
    center = len(binary_string) // 2
    left = binary_string[:center]
    right = binary_string[center:]
    for key in keys:
        left, right = right, xor_string(encryption_func(right, key), left)
    return right + left


def feistel_decrypt(binary_string, keys, encryption_func):
    return feistel_encrypt(binary_string, keys[::-1], encryption_func)


def get_des_feistel_func(extension_table, basic_conversion_table, final_permutation_table):
    def des_feistel_func(binary_string, key, ):
        cipher_string = permute(binary_string, extension_table)
        chunks = chunk_str(xor_string(cipher_string, key), len(cipher_string) // 8)
        after_basic_conversion = ""
        for i, chunk in enumerate(chunks):
            row = int(chunk[0] + chunk[-1], 2)
            column = int(chunk[1:-1], 2)
            after_basic_conversion += to_binary_str(basic_conversion_table[i][row][column], 4)
        return permute(after_basic_conversion, final_permutation_table)

    return des_feistel_func


def des_encrypt(text, binary_key, appended_letter,
                ip_permutation,
                extension_table, basic_conversion_table, final_permutation_table,
                initial_key_permutation, round_keys_shifts, final_key_permutation,
                reverse_ip_permutation):
    keys = get_round_keys(binary_key, initial_key_permutation, round_keys_shifts, final_key_permutation)
    binary_codes = [to_binary(chunk) for chunk in chunk_str(text, 8, appended_letter)]
    result = []
    for code in binary_codes:
        cipher_text = permute(code, ip_permutation)
        cipher_text = feistel_encrypt(cipher_text, keys, get_des_feistel_func(extension_table, basic_conversion_table,
                                                                              final_permutation_table))
        result.append(permute(cipher_text, reverse_ip_permutation))
    return result


def des_decrypt(text, binary_key, appended_letter,
                ip_permutation,
                extension_table, basic_conversion_table, final_permutation_table,
                initial_key_permutation, round_keys_shifts, final_key_permutation,
                reverse_ip_permutation):
    keys = get_round_keys(binary_key, initial_key_permutation, round_keys_shifts, final_key_permutation)
    # binary_codes = [to_binary(chunk) for chunk in chunk_str(text, 8, appended_letter)]
    binary_codes = chunk_str(text, 64, appended_letter)
    result = []
    for code in binary_codes:
        cipher_text = permute(code, ip_permutation)
        cipher_text = feistel_decrypt(cipher_text, keys, get_des_feistel_func(extension_table, basic_conversion_table,
                                                                              final_permutation_table))
        result.append(permute(cipher_text, reverse_ip_permutation))
    return result


if __name__ == "__main__":
    print("Start!")
    input_text = "abcdefgh"

    des_key = to_binary('kwansta')
    cipher_blocks = des_encrypt(input_text, des_key, APPENDED_LETTER,
                                IP_PERMUTATION, EXTENSION_TABLE, BASIC_CONVERSION_TABLES,
                                FINAL_DES_FUNCTION_PERMUTATION,
                                INITIAL_KEY_PERMUTATION, ROUND_KEYS_SHIFTS, FINAL_KEY_PERMUTATION,
                                REVERSE_IP_PERMUTATION)
    for block in cipher_blocks:
        print(block)
        print(from_binary(block))
        dec = des_decrypt(block, des_key, APPENDED_LETTER,
                          IP_PERMUTATION, EXTENSION_TABLE, BASIC_CONVERSION_TABLES,
                          FINAL_DES_FUNCTION_PERMUTATION,
                          INITIAL_KEY_PERMUTATION, ROUND_KEYS_SHIFTS, FINAL_KEY_PERMUTATION,
                          REVERSE_IP_PERMUTATION)
        print(from_binary(dec[0], APPENDED_LETTER))
    # c_key = '0001001100110100010101110111100110011011101111001101111111110001'
    # for k in get_round_keys(c_key, INITIAL_KEY_PERMUTATION, ROUND_KEYS_SHIFTS, FINAL_KEY_PERMUTATION):
    #     print(k)
