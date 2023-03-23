def get_version_name_for_database(version_name: str):
    """This function prepares the version_name to be usable in the database as art of a table's name"""
    version_name = version_name if "Unnamed" not in version_name else ""
    version_name = version_name.strip().title().replace(" ", "").replace("-", "").replace("/", "_").replace("#", "") \
        .strip(".")
    return version_name.upper()


def get_standard_name_for_database(standard_name):
    """
    This function prepares the standard_name to be usable in the database as part of a table's name
    :param: standard_name: The standard_name to sanitize
    :type standard_name: str
    """
    if " " in standard_name:
        tokens = standard_name.split(" ")
        if "+" in tokens[1]:
            # The "added" entries are already present in the dict
            standard_name = tokens[0]
        elif len(tokens) > 2 and "/" in tokens[-1]:
            standard_name = tokens[0] + tokens[-1].replace("/", "_")
    return standard_name.strip(")").upper()


def get_standardized_level(level):
    """
    Takes a level in input and returns it after removing °,* and trailing spaces
    :param level:
    :type level: str
    :return:
    """
    return level.replace("*", "").replace("°", "").strip()
