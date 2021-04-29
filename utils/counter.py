import re


def count_occurrencies(word: str, input_string: str) -> int:
    return sum(1 for _ in re.finditer(r"\b%s\b" % re.escape(word), input_string))
