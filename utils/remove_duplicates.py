from collections import OrderedDict


def remove_duplicates(string: str, line_sep: str) -> str:
    """
    Remove duplicates from a string.

    :param string: The string to process.
    :type string: str
    :param line_sep: The line separator.
    :type line_sep: str
    :return: The string without duplicates.
    :rtype: str
    """
    return line_sep.join(OrderedDict.fromkeys(string.split(line_sep)))