import logging


class Validator:
    def __init__(self, args=None):
        counter = 0
        prefix = "[VALIDATOR] "
        if args and isinstance(args, list):
            for value in args:
                logging.debug(f"{prefix}Processing tuple no {counter}")
                counter += 1
                if isinstance(value, tuple) and len(value) == 2:
                    var, type_to_check = value
                    self.obj(var, type_to_check)

    def __check(self, obj, _type, raise_error=True):
        if isinstance(obj, _type):
            return True
        elif raise_error:
            raise TypeError(f"Expected {_type}, found {type(obj)}")
        else:
            return False

    def bool(self, obj, raise_error=True) -> bool:
        """
        Type check obj and return True if ok, else raise error (or return false)
        :param obj: The object to type check
        :param raise_error: Raise the error if any.
        :type raise_error: bool
        :return: True if type check, Raise TypeError or False if mismatch
        :rtype: bool
        :raise TypeError: If type mismatch
        """
        return self.__check(obj, bool, raise_error)

    def string(self, obj, raise_error=True) -> bool:
        """
        Type check obj and return True if ok, else raise error (or return false)
        :param obj: The object to type check
        :param raise_error: Raise the error if any.
        :type raise_error: bool
        :return: True if type check, Raise TypeError or False if mismatch
        :rtype: bool
        :raise TypeError: If type mismatch
        """
        return self.__check(obj, str, raise_error)

    def list(self, obj, raise_error=True) -> bool:
        """
        Type check obj and return True if ok, else raise error (or return false)
        :param obj: The object to type check
        :param raise_error: Raise the error if any.
        :type raise_error: bool
        :return: True if type check, Raise TypeError or False if mismatch
        :rtype: bool
        :raise TypeError: If type mismatch
        """
        return self.__check(obj, list, raise_error)

    def dict(self, obj, raise_error=True) -> bool:
        """
        Type check obj and return True if ok, else raise error (or return false)
        :param obj: The object to type check
        :param raise_error: Raise the error if any.
        :type raise_error: bool
        :return: True if type check, Raise TypeError or False if mismatch
        :rtype: bool
        :raise TypeError: If type mismatch
        """
        return self.__check(obj, dict, raise_error)

    def int_or_float(self, obj, raise_error=True) -> bool:
        """
        Type check obj and return True if ok, else raise error (or return false)
        :param obj: The object to type check
        :param raise_error: Raise the error if any.
        :type raise_error: bool
        :return: True if type check, Raise TypeError or False if mismatch
        :rtype: bool
        :raise TypeError: If type mismatch
        """
        return self.__check(obj, (int, float), raise_error)

    def int(self, obj, raise_error=True) -> bool:
        """
        Type check obj and return True if ok, else raise error (or return false)
        :param obj: The object to type check
        :param raise_error: Raise the error if any.
        :type raise_error: bool
        :return: True if type check, Raise TypeError or False if mismatch
        :rtype: bool
        :raise TypeError: If type mismatch
        """
        return self.__check(obj, int, raise_error)

    def float(self, obj, raise_error=True) -> bool:
        """
        Type check obj and return True if ok, else raise error (or return false)
        :param obj: The object to type check
        :param raise_error: Raise the error if any.
        :type raise_error: bool
        :return: True if type check, Raise TypeError or False if mismatch
        :rtype: bool
        :raise TypeError: If type mismatch
        """
        return self.__check(obj, float, raise_error)

    def obj(self, obj, type_obj, raise_error=True) -> bool:
        """
        Type check obj and return True if ok, else raise error (or return false)
        :param obj: The object to type check
        :param raise_error: Raise the error if any.
        :param type_obj: Type to check
        :type raise_error: bool
        :return: True if type check, Raise TypeError or False if mismatch
        :rtype: bool
        :raise TypeError: If type mismatch
        """
        return self.__check(obj, type_obj, raise_error)
