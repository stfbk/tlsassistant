from jsonmerge import Merger

from utils.colors import Color


def merge(base: dict, head: dict) -> dict:
    """
    Merge base with head dict.

    :param base: dict to get merged with head.
    :type base: dict
    :param head: dict to merge in base.
    :type head: dict
    :return: The merged dict.
    :rtype: dict
    """
    merger = Merger(
        {
            "oneOf": [
                {"type": "array", "mergeStrategy": "append"},
                {"type": "object", "additionalProperties": {"$ref": "#"}},
                {"type": "string"},
                {"type": "number"},
            ]
        }
    )
    return merger.merge(base, head)


def pretty(d, indent: int = 0, is_list: bool = False):
    """
    Pretty print dict.

    :param d: Dict or list to print in pretty mode
    :param indent: Intentation level.
    :type indent: int
    :param is_list: is it a list? recursive parameter
    :type is_list: bool
    """
    if not is_list:
        for key, value in d.items():
            print("\t" * indent + f"{Color.CBEIGE} {key}{Color.ENDC}")
            __print_pretty_value(value, indent)
    else:
        for value in d:
            __print_pretty_value(value, indent)


def __print_pretty_value(value, indent):
    """
    Print a list of dicts in pretty mode.
    """
    if isinstance(value, dict):
        pretty(value, indent + 1)
    elif isinstance(value, list):
        pretty(value, indent + 1, is_list=True)
    else:
        print("\t" * (indent + 1) + f"{value}")

def get_aliases():
    aliases = {
        "poodle" : ["tlspoodle","sslpoodle"]
    }
    return aliases