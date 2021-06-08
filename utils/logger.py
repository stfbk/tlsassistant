import logging
from utils.configuration import Color


class Logger:
    def __init__(self, obj):
        if isinstance(obj, str):
            self.__class_name = obj
        elif isinstance(obj, object):
            self.__class_name = object.__class__.__name__
        else:
            raise TypeError(
                f"Obj is of type {type(obj)}, the required type is 'str' or 'object'"
            )

    def debug(self, string: str):
        logging.debug(f"[{self.__class_name}]{string}")

    def warning(self, string: str):
        logging.warning(f"{Color.WARNING}[{self.__class_name}]{string}{Color.ENDC}")

    def info(self, string: str):
        logging.info(f"{Color.CGREEN}[{self.__class_name}]{string}{Color.ENDC}")

    def error(self, string: str):
        logging.error(f"{Color.FAIL}[{self.__class_name}]{string}{Color.ENDC}")
