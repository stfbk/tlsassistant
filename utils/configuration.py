from enum import Enum

from jsonmerge import Merger


def merge(base, head):
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


def pretty(d, indent=0, is_list=False):
    if not is_list:
        for key, value in d.items():
            print("\t" * indent + f"{Color.CBEIGE} {key}{Color.ENDC}")
            __print_pretty_value(value, indent)
    else:
        for value in d:
            __print_pretty_value(value, indent)


def __print_pretty_value(value, indent):
    if isinstance(value, dict):
        pretty(value, indent + 1)
    elif isinstance(value, list):
        pretty(value, indent + 1, is_list=True)
    else:
        print("\t" * (indent + 1) + f"{value}")


class Color:
    HEADER = "\33[95m"
    OKBLUE = "\33[94m"
    OKCYAN = "\33[96m"
    OKGREEN = "\33[92m"
    WARNING = "\33[93m"
    FAIL = "\33[91m"
    ENDC = "\33[0m"
    BOLD = "\33[1m"
    UNDERLINE = "\33[4m"

    CEND = "\33[0m"
    CBOLD = "\33[1m"
    CITALIC = "\33[3m"
    CURL = "\33[4m"
    CBLINK = "\33[5m"
    CBLINK2 = "\33[6m"
    CSELECTED = "\33[7m"

    CBLACK = "\33[30m"
    CRED = "\33[31m"
    CGREEN = "\33[32m"
    CYELLOW = "\33[33m"
    CBLUE = "\33[34m"
    CVIOLET = "\33[35m"
    CBEIGE = "\33[36m"
    CWHITE = "\33[37m"

    CBLACKBG = "\33[40m"
    CREDBG = "\33[41m"
    CGREENBG = "\33[42m"
    CYELLOWBG = "\33[43m"
    CBLUEBG = "\33[44m"
    CVIOLETBG = "\33[45m"
    CBEIGEBG = "\33[46m"
    CWHITEBG = "\33[47m"

    CGREY = "\33[90m"
    CRED2 = "\33[91m"
    CGREEN2 = "\33[92m"
    CYELLOW2 = "\33[93m"
    CBLUE2 = "\33[94m"
    CVIOLET2 = "\33[95m"
    CBEIGE2 = "\33[96m"
    CWHITE2 = "\33[97m"

    CGREYBG = "\33[100m"
    CREDBG2 = "\33[101m"
    CGREENBG2 = "\33[102m"
    CYELLOWBG2 = "\33[103m"
    CBLUEBG2 = "\33[104m"
    CVIOLETBG2 = "\33[105m"
    CBEIGEBG2 = "\33[106m"
    CWHITEBG2 = "\33[107m"
