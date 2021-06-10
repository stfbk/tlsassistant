import logging


class Logger:
    def __init__(self, obj):
        """
        Logger to log errors and other messages

        :param obj: Obj (automatically gets type name) or name as a string.
        :type obj: str or obj
        :raise TypeError: If string or obj different
        """
        if isinstance(obj, str):
            self.__class_name = obj
        elif isinstance(obj, object):
            self.__class_name = object.__class__.__name__
        else:
            raise TypeError(
                f"Obj is of type {type(obj)}, the required type is 'str' or 'object'"
            )

    def debug(self, string: str):
        """
        Prints debug message.

        :param string: The string message.
        :type string: str
        """
        logging.debug(f"[{self.__class_name}]{string}")

    def warning(self, string: str):
        """
        Prints warn message.

        :param string: The string message.
        :type string: str
        """
        logging.warning(f"{Color.WARNING}[{self.__class_name}]{string}{Color.ENDC}")

    def info(self, string: str):
        """
        Prints info message.

        :param string: The string message.
        :type string: str
        """
        logging.info(f"{Color.CGREEN}[{self.__class_name}]{string}{Color.ENDC}")

    def error(self, string: str):
        """
        Prints error message.

        :param string: The string message.
        :type string: str
        """
        logging.error(f"{Color.FAIL}[{self.__class_name}]{string}{Color.ENDC}")


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