from des.utils.string_processing import chunk_str


def number_to_binary_str(number, length=8):
    return f"{number:0{length}b}"


def to_binary(text):
    return "".join([number_to_binary_str(ord(letter)) for letter in text])


def from_binary(binary_text, appended_letter=None):
    return "".join(
        [chr(int(chunk, 2)) for chunk in chunk_str(binary_text, 8) if
         appended_letter is None or chunk != number_to_binary_str(ord(appended_letter))]
    )


# leaves leading zeros
def xor_string(first_str, second_str):
    result_len = max(len(first_str), len(second_str))
    return f"{(int(first_str, 2) ^ int(second_str, 2)):0{result_len}b}"


def add_parity_bits(binary_string, calculate_bit=lambda last_bits: "0"):
    result = []
    for i in range(0, len(binary_string), 7):
        chunk = binary_string[i: i + 7]
        result += binary_string[i: i + 7] + calculate_bit(chunk)
    return ''.join(result)
