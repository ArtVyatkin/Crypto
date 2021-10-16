from functools import reduce
from typing import List
import numpy as np

from src.aes.config import (
    RCON,
    S_BOX,
    BIAS_SHIFTS,
    GALOIS_MUL,
    MIX_COLUMN_MATRIX,
    INVERSE_SUB_BOX,
    INVERSE_MIX_COLUMN_MATRIX,
    APPENDED_BYTE,
)
from src.utils.std_stream import check_encryption_algorithm_with_user, InputStringHandlerTypes

N_BYTES_IN_WORD = 4
N_WORDS_IN_BLOCK = 4
N_BYTES_IN_BLOCK = N_BYTES_IN_WORD * N_WORDS_IN_BLOCK
N_ROUNDS = 10


def hex_text_to_numbers(hex_text):
    return [int(f"0x{byte}", 16) for byte in hex_text.split()]


def table_from_text(hex_text, n_bytes_in_word, n_bytes_in_block):
    hex_text_as_numbers = hex_text_to_numbers(hex_text)
    return [hex_text_as_numbers[i: n_bytes_in_word + i] for i in range(0, n_bytes_in_block, n_bytes_in_word)]


def shift(input_list, shift_value, is_left_shift=True):
    shift_value = shift_value * (1 if is_left_shift else -1)
    return list(input_list[shift_value:]) + list(input_list[:shift_value])


def sub_bytes(byte_list, s_box):
    return [s_box[byte // 16][byte % 16] for byte in byte_list]


def xor_words(first_word, second_word):
    return [first_byte ^ second_byte for first_byte, second_byte in zip(first_word, second_word)]


def expand_key(hex_key, n_rounds, rcon, n_word_in_block, s_box):
    key_schedule = table_from_text(hex_key, N_BYTES_IN_WORD, N_BYTES_IN_BLOCK)
    for i in range(n_rounds):
        new_word = shift(key_schedule[-1], 1)
        new_word = sub_bytes(new_word, s_box)
        new_word = xor_words(new_word, xor_words(rcon[i], key_schedule[-4]))
        key_schedule.append(new_word)
        for j in range(n_word_in_block - 1):
            key_schedule.append(xor_words(key_schedule[-1], key_schedule[-4]))
    return key_schedule


def add_round_key(state, key_schedule, round_number, n_words_in_bock):
    """round_number starts at 0."""
    return [
        xor_words(state_word, key_word)
        for state_word, key_word in zip(
            state, key_schedule[round_number * n_words_in_bock: (round_number + 1) * n_words_in_bock]
        )
    ]


def shift_columns(table: List[List[float]], bias_number_list, is_left_shift=True) -> List[List[int]]:
    transpose_table = np.transpose(np.array(table))
    for j in range(len(transpose_table)):
        transpose_table[j] = shift(transpose_table[j], bias_number_list[j], is_left_shift=is_left_shift)
    # noinspection PyTypeChecker
    return transpose_table.transpose().tolist()


def galois_mul(first_value, second_value):
    if first_value == 1:
        return second_value
    else:
        return GALOIS_MUL[first_value][second_value]


def scalar_dot_in_galois(first_vector, second_vector):
    terms = [galois_mul(first_value, second_value) for first_value, second_value in zip(first_vector, second_vector)]
    return reduce(lambda x, y: x ^ y, terms)


def mix_rows(state, mix_column_matrix):
    result = []
    matrix_len = len(mix_column_matrix)
    for row in state:
        result.append([scalar_dot_in_galois(mix_column_matrix[i], row) for i in range(matrix_len)])
    return result


def state_to_text(state):
    return " ".join([" ".join([f"{byte:02x}".upper() for byte in word]) for word in state])


def chunk_hex_str(hex_str, bytes_in_chunk, appended_hex=None):
    hex_as_list = hex_str.split()
    if appended_hex is not None:
        number_of_last_bytes = len(hex_as_list) % bytes_in_chunk
        if number_of_last_bytes != 0:
            hex_as_list += [appended_hex] * (bytes_in_chunk - number_of_last_bytes)
    return [" ".join(hex_as_list[i: i + bytes_in_chunk]) for i in range(0, len(hex_as_list), bytes_in_chunk)]


def remove_last_appended_bytes(hex_text, appended_bytes):
    terms = hex_text.split()
    i = len(terms)
    while terms[i - 1] == appended_bytes and i - 1 >= 0:
        i -= 1
    return " ".join(terms[:i])


def aes_encrypt(hex_text, hex_key):
    hex_chunks = chunk_hex_str(hex_text, N_BYTES_IN_BLOCK, APPENDED_BYTE)
    result = []
    for chunk in hex_chunks:
        state = table_from_text(chunk, N_BYTES_IN_WORD, N_BYTES_IN_BLOCK)
        key_schedule = expand_key(hex_key, N_ROUNDS, RCON, N_WORDS_IN_BLOCK, S_BOX)
        state = add_round_key(state, key_schedule, 0, N_WORDS_IN_BLOCK)
        for i in range(1, N_ROUNDS):
            state = [sub_bytes(word, S_BOX) for word in state]
            state = shift_columns(state, BIAS_SHIFTS)
            state = mix_rows(state, MIX_COLUMN_MATRIX)
            state = add_round_key(state, key_schedule, i, N_WORDS_IN_BLOCK)
        state = [sub_bytes(word, S_BOX) for word in state]
        state = shift_columns(state, BIAS_SHIFTS)
        state = add_round_key(state, key_schedule, N_ROUNDS, N_WORDS_IN_BLOCK)
        result.append(state_to_text(state))
    return " ".join(result)


def aes_decrypt(cipher_hex_text, hex_key):
    hex_chunks = chunk_hex_str(cipher_hex_text, N_BYTES_IN_BLOCK, APPENDED_BYTE)
    result = []
    for chunk in hex_chunks:
        state = table_from_text(chunk, N_BYTES_IN_WORD, N_BYTES_IN_BLOCK)
        key_schedule = expand_key(hex_key, N_ROUNDS, RCON, N_WORDS_IN_BLOCK, S_BOX)
        state = add_round_key(state, key_schedule, N_ROUNDS, N_WORDS_IN_BLOCK)
        for i in range(N_ROUNDS - 1, 0, -1):
            state = shift_columns(state, BIAS_SHIFTS, is_left_shift=False)
            state = [sub_bytes(word, INVERSE_SUB_BOX) for word in state]
            state = add_round_key(state, key_schedule, i, N_WORDS_IN_BLOCK)
            state = mix_rows(state, INVERSE_MIX_COLUMN_MATRIX)
        state = shift_columns(state, BIAS_SHIFTS, is_left_shift=False)
        state = [sub_bytes(word, INVERSE_SUB_BOX) for word in state]
        state = add_round_key(state, key_schedule, 0, N_WORDS_IN_BLOCK)
        result.append(remove_last_appended_bytes(state_to_text(state), APPENDED_BYTE))
    return " ".join(result)


if __name__ == "__main__":
    # Example:
    # key: '2b7e1511283ed2a61bf7138809cf4d4c'
    # text: 'London is the capital of Great Britain!'
    check_encryption_algorithm_with_user("AES", 32, aes_encrypt, aes_decrypt, InputStringHandlerTypes.HEX)
