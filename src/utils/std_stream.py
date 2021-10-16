import re
from enum import Enum, auto

from src.utils.encodings_processing import to_binary, binary_to_hex, hex_to_binary, from_binary
from src.utils.strinig_processing import chunk_str


def input_hex(str_length):
    hex_str = None
    while hex_str is None:
        hex_str = input().lower().replace(" ", "")
        if re.fullmatch(r"[a-f0-9]+", hex_str) is None:
            print("Please enter the string in HEX format.")
            hex_str = None
        elif len(hex_str) != str_length:
            print(f"Please enter a string with exactly {str_length} HEX characters.")
            hex_str = None
    return hex_str


def get_hex_to_display(hex_str):
    return " ".join([chunk.upper() for chunk in chunk_str(hex_str, 2)])


class InputStringHandlerTypes(Enum):
    BINARY = auto()
    HEX = auto()
    ASCII = auto()


INPUT_STRING_HANDLERS = {
    InputStringHandlerTypes.BINARY: to_binary,
    InputStringHandlerTypes.HEX: lambda t: get_hex_to_display(binary_to_hex(to_binary(t))),
    InputStringHandlerTypes.ASCII: lambda t: t,
}


def check_encryption_algorithm_with_user(
    algorithm_name, n_hex_characters_in_key, encrypt_function, decrypt_function, input_string_type
):
    print(f"===================={algorithm_name}====================")
    print("Enter a string to encrypt:")
    ascii_string = input()
    print(f"Enter a key in HEX format with exactly {n_hex_characters_in_key} characters:")
    cur_hex_key = get_hex_to_display(input_hex(n_hex_characters_in_key))
    print(f"HEX key: '{cur_hex_key}'")
    encrypted_string = encrypt_function(INPUT_STRING_HANDLERS[input_string_type](ascii_string), cur_hex_key)

    print(f"Encrypted string in HEX: '{encrypted_string}'")
    decrypted_string = decrypt_function(encrypted_string, cur_hex_key)
    print(
        f"String after decryption: '{decrypted_string if input_string_type == InputStringHandlerTypes.ASCII else from_binary(hex_to_binary(decrypted_string))}'"
    )
