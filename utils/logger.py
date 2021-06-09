import logging
from utils.configuration import Color


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
