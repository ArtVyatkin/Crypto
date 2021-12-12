from random import randint
from typing import Tuple

from bitarray import bitarray
from bitarray.util import ba2int

from src.schnorr_signature.config import PRIME_CONSTANTS
from src.schnorr_signature.utils import int2sha_bin, bin_str2int, int2hex_str
from src.sha256.main import sha256
from src.utils.encodings_processing import number_to_binary_str, to_binary, binary_to_hex


def get_number_representation(number):
    """An auxiliary function for Miller-Rabin test."""

    number = number - 1
    a = 1
    two_power = 2
    while number % two_power == 0:
        a += 1
        two_power *= 2
    a -= 1
    m = number // (two_power // 2)
    return a, m


def is_prime(n, k=60):
    """A probabilistic primality Miller-Rabin test."""

    from random import randint

    if n < 2:
        return False
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]:
        if n % p == 0:
            return n == p
    s, d = get_number_representation(n)
    for i in range(k):
        x = pow(randint(2, n - 1), d, n)
        if x == 1 or x == n - 1:
            continue
        for r in range(1, s):
            x = pow(x, 2, n)
            if x == 1:
                return False
            if x == n - 1:
                break
        else:
            return False
    return True


def get_prime_numbers():
    hash_bit_count = 256
    L = 2048
    max_q_modulo = 2 ** hash_bit_count
    two_pow_L_minus_1 = 2 ** (L - 1)

    zeros = "0" * 255
    seed = None
    almost_max_q_modulo = bitarray("1" + zeros)
    one_expanded = bitarray(zeros + "1")

    offset = 2
    n = 7
    two_powers = [2 ** i for i in range(n + 1)]
    b = 255

    p = None
    q = None

    while p is None:
        q = None
        while q is None or not is_prime(ba2int(q)):
            seed = randint(2, 2 ** 32)

            u = bitarray(int2sha_bin(seed)) ^ bitarray(int2sha_bin((seed + 1) % max_q_modulo))
            q = u | almost_max_q_modulo | one_expanded

        for counter in range(0, 4096):
            v = []
            for k in range(n + 1):
                bin_v = int2sha_bin((seed + offset + k) % max_q_modulo)
                v.append(bin_str2int(bin_v))
            w = v[0]
            for i, v_i in enumerate(v[1:-1]):
                w += v_i * max_q_modulo * two_powers[i + 1]

            w += (v[n] % (2 ** b)) * max_q_modulo * two_powers[n]

            x = w + two_pow_L_minus_1
            c = x % (2 * ba2int(q))
            p_candidate = x - c + 1
            if p_candidate > two_pow_L_minus_1 and is_prime(p_candidate):
                p = p_candidate
                break
            offset += n + 1
    return p, ba2int(q)


def get_domain_parameters(use_ready_made_numbers=True):
    """q ~ 2^256, g ~ 2^2048"""

    if use_ready_made_numbers:
        p, q = PRIME_CONSTANTS[randint(0, len(PRIME_CONSTANTS) - 1)]
    else:
        p, q = get_prime_numbers()

    g = None
    k = (p - 1) // q
    while g is None or g == 1:
        h = randint(1, p - 1)
        g = pow(h, k, p)

    return {"p": p, "q": q, "g": g}


def generate_keys(domain_params):
    private_key = randint(1, domain_params["q"] - 1)
    public_key = pow(domain_params["g"], domain_params["q"] - private_key, domain_params["p"])
    return private_key, public_key


def get_first_sign_part(message, r, domain_params):
    return int(sha256(to_binary(message) + number_to_binary_str(r)), 2) % domain_params["q"]


def sign(message, domain_params, private_key):
    k = randint(1, domain_params["q"] - 1)
    r = pow(domain_params["g"], k, domain_params["p"])
    first_signature_part = get_first_sign_part(message, r, domain_params)
    second_signature_part = (k + private_key * first_signature_part) % domain_params["q"]
    return first_signature_part, second_signature_part


def is_signature_correct(message, signature: Tuple[int, int], public_key, domain_params):
    r = (
        pow(domain_params["g"], signature[1], domain_params["p"])
        * pow(public_key, signature[0], domain_params["p"])
        % domain_params["p"]
    )
    return signature[0] == get_first_sign_part(message, r, domain_params)


def print_result(message, signature, public_key, domain_params):
    print(
        f"Is signature correct: {'yes' if is_signature_correct(message, signature, public_key, domain_params) else 'no'}"
    )


def print_signature(signature, is_correct=True):
    print(f"\n{'Signature' if is_correct else 'Incorrect signature'}:")
    print(f"    First part: {int2hex_str(signature[0])}")
    print(f"    Second part: {int2hex_str(signature[1])}")


if __name__ == "__main__":
    print(f"====================Schnorr signature====================")
    domain_params_ = get_domain_parameters(use_ready_made_numbers=True)
    print("Domain parameters:")
    for key, value in domain_params_.items():
        print(f"    {key}: {int2hex_str(value)}")

    private_key_, public_key_ = generate_keys(domain_params_)
    print(f"Private key: {int2hex_str(private_key_)}")
    print(f"Public key: {int2hex_str(public_key_)}")

    print("\nEnter a message to sign:")
    # Never gonna give you up, never gonna let you down, never gonna run around and desert you
    input_str = input()

    signature_ = sign(input_str, domain_params_, private_key_)

    print_signature(signature_)
    print_result(input_str, signature_, public_key_, domain_params_)

    incorrect_signature = (signature_[0], signature_[1] + 1)

    print_signature(incorrect_signature, is_correct=False)
    print_result(input_str, incorrect_signature, public_key_, domain_params_)
