import re


def count_occurrencies(word: str, input_string: str) -> int:
    """
    Count word occurrences in a string.

    :param word: The word to find.
    :type word: str
    :param input_string: The input string where to search
    :type input_string: str
    :return: Counted occurrences.
    :rtype: str
    """
    return sum(1 for _ in re.finditer(r"\b%s\b" % re.escape(word), input_string))
