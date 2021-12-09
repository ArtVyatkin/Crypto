from bitarray import bitarray
from bitarray.util import int2ba as int2ba_from_lib, ba2int

from src.aes.main import shift
from src.sha256.config import (
    K,
    H,
    WORD_LENGTH,
    INITIAL_REMAINDER,
    BLOCK_LENGTH,
    NUMBER_OF_BITS_WITH_MESSAGE_LENGTH,
    NUMBER_OF_ITERATIONS,
    MODULO,
)
from src.utils.encodings_processing import binary_to_hex, to_binary


def int2ba(number, length=WORD_LENGTH):
    return int2ba_from_lib(number, length)


def chunk_str(input_str_, symbols_in_chunk):
    return [input_str_[i: i + symbols_in_chunk] for i in range(0, len(input_str_), symbols_in_chunk)]


def right_shift(input_bitarray, shift_value):
    return bitarray(shift(input_bitarray, shift_value, is_left_shift=False))


def to_bitarray_list(input_list, word_length=32):
    return [int2ba(number, length=word_length) for number in input_list]


def sum_by_modulo(list_to_sum, modulo):
    return sum(list_to_sum) % modulo


K = to_bitarray_list(K)


def prepare_string(bit_str):
    bit_message = bitarray(bit_str) + bitarray("1")
    remainder = len(bit_message) % BLOCK_LENGTH
    bit_message += (
        (INITIAL_REMAINDER - remainder) * "0"
        if remainder <= INITIAL_REMAINDER
        else (INITIAL_REMAINDER + BLOCK_LENGTH - remainder) * "0"
    )
    return bit_message + int2ba(len(bit_str), length=NUMBER_OF_BITS_WITH_MESSAGE_LENGTH)


def expand_words(words):
    for i in range(int(BLOCK_LENGTH / WORD_LENGTH), NUMBER_OF_ITERATIONS):
        s0 = right_shift(words[i - 15], 7) ^ right_shift(words[i - 15], 18) ^ (words[i - 15] >> 3)
        s1 = right_shift(words[i - 2], 17) ^ right_shift(words[i - 2], 19) ^ (words[i - 2] >> 10)
        word_as_int = sum_by_modulo([ba2int(words[i - 16]), ba2int(s0), ba2int(words[i - 7]), ba2int(s1)], MODULO)
        words.append(int2ba(word_as_int))


def get_handled_supporting_vars(main_vars, words):
    a, b, c, d, e, f, g, h = main_vars

    for i in range(NUMBER_OF_ITERATIONS):
        summ_0 = right_shift(a, 2) ^ right_shift(a, 13) ^ right_shift(a, 22)
        m_a = (a & b) ^ (a & c) ^ (b & c)
        t2 = sum_by_modulo([ba2int(summ_0), ba2int(m_a)], MODULO)  # int
        summ_1 = right_shift(e, 6) ^ right_shift(e, 11) ^ right_shift(e, 25)
        c_h = (e & f) ^ (~e & g)
        t1 = sum_by_modulo([ba2int(h), ba2int(summ_1), ba2int(c_h), ba2int(K[i]), ba2int(words[i])], MODULO)  # int

        # fmt: off
        a, b, c, d, e, f, g, h = (
            int2ba(sum_by_modulo([t1, t2], MODULO)),
            a, b, c,
            int2ba(sum_by_modulo([t1, ba2int(d)], MODULO)),
            e, f, g,
        )
        # fmt: on
    return a, b, c, d, e, f, g, h


def sha256(bit_str: str) -> str:
    """str with '0's and '1's -> str with '0's and '1's"""

    h0, h1, h2, h3, h4, h5, h6, h7 = to_bitarray_list(H)
    bit_message = prepare_string(bit_str)
    for chunk in chunk_str(bit_message, BLOCK_LENGTH):
        words = chunk_str(chunk, WORD_LENGTH)
        expand_words(words)
        handled_supporting_vars = get_handled_supporting_vars((h0, h1, h2, h3, h4, h5, h6, h7), words)

        h0, h1, h2, h3, h4, h5, h6, h7 = (
            int2ba(sum_by_modulo([ba2int(n1), ba2int(n2)], MODULO))
            for n1, n2 in zip((h0, h1, h2, h3, h4, h5, h6, h7), handled_supporting_vars)
        )

    return (h0 + h1 + h2 + h3 + h4 + h5 + h6 + h7).to01()


if __name__ == "__main__":
    print(f"====================SHA-256====================")
    print("Enter a string to hash:")
    # To be, or not to be, that is the question: Whether 'tis nobler in the mind to suffer ...
    bit_string = to_binary(input())
    print("Hashed string:")
    print(binary_to_hex(sha256(bit_string)))
