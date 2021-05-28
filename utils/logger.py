import logging


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

    def warn(self, string: str):
        logging.warning(f"[{self.__class_name}]{string}")

    def info(self, string: str):
        logging.info(f"[{self.__class_name}]{string}")

    def error(self, string: str):
        logging.error(f"[{self.__class_name}]{string}")
