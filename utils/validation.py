import logging


def rec_search_key(key, var, wildcard=False, return_keys=False, case_sensitive=True):
    """
    Search a key in a dict or list recursively.

    :param key: The key to search for.
    :type key: str
    :param var: The dict or list to search in.
    :type var: dict or list
    :param wildcard: If True, the key can contain wildcards.
    :type wildcard: bool
    :param return_keys: If True, return the keys of the found items instead of the items themselves.
    :type return_keys: bool
    :param case_sensitive: If True, the search will be case sensitive.
    :type case_sensitive: bool
    :return: The found items.
    :rtype: Generator

    """
    if hasattr(var, "items"):
        for k, v in var.items():
            condition = (
                (key in k if case_sensitive else key.lower() in k.lower())
                if wildcard
                else (k == key if case_sensitive else k.lower() == key.lower())
            )
            if condition:
                yield (k, v) if return_keys else v
            if isinstance(v, dict):
                for result in rec_search_key(
                    key, v, wildcard, return_keys, case_sensitive
                ):
                    yield result
            elif isinstance(v, list):
                for d in v:
                    for result in rec_search_key(
                        key, d, wildcard, return_keys, case_sensitive
                    ):
                        yield result


def is_apk(module):
    """
    Check if a module is APK related.

    :param module: The module to check.
    :type module: Module
    :return: True if the module is APK related.
    :rtype: bool
    """
    return hasattr(module, "is_android")

def is_ipa(module):
    """
    Check if a module is IPA related.

    :param module: The module to check.
    :type module: Module
    :return: True if the module is IPA related.
    :rtype: bool
    """
    return hasattr(module, "is_ios")


class Validator:
    """
    Validate type given.

    """

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
        """
        Internal function to check the type of an object.
        :param obj: The object to type check
        :param _type: The type to check against
        :param raise_error: Raise the error if any.
        :type raise_error: bool
        :return: True if type check, Raise TypeError or False if mismatch
        :rtype: bool
        :raise TypeError: If type mismatch
        """
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
