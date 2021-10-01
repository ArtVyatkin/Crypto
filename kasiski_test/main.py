from collections import Counter
from math import floor, sqrt


def find_all_divisors(number):
    divisors = set()
    for j in range(1, floor(sqrt(number) + 1)):
        if number % j == 0:
            divisors.add(j)
            divisors.add(number // j)
    return divisors


def get_possible_lengths(text, substring_length):
    substrings_indexes = {}
    possible_lengths = Counter()

    for j in range(len(text) - substring_length + 1):
        substring = text[j : j + substring_length]
        if substring not in substrings_indexes:
            substrings_indexes.update({substring: j})
        else:
            possible_lengths.update(find_all_divisors(j - substrings_indexes[substring]))
            substrings_indexes[substring] = j

    return possible_lengths


if __name__ == "__main__":
    with open("input.txt", "r") as f:
        cipher_text = f.read().lower().replace(" ", "")
    all_possible_lengths = Counter()

    for i in range(3, 4):
        print("a")
        all_possible_lengths.update(get_possible_lengths(cipher_text, 3))

    for length, freq in sorted(all_possible_lengths.items()):
        print(f"{length} -- {freq}")
