from modules.stix.stix_base import Bundled
from utils.logger import Logger
from utils.validation import Validator


class Stix:
    """
    This class is used to create a STIX bundle for each module.
    """

    def __init__(self):
        self.__logger = Logger("STIX")

    def run(self, modules):
        self.__logger.info("Generating STIX for modules...")
        Validator(
            [
                (modules, dict)
            ]
        )
        res = {}
        for module, loaded_module in modules.items():
            if self.__check_module(loaded_module):  # checks for STIX bundle wrapper class
                # if ok, then run and obtain
                self.__logger.debug(f"Generating STIX for module: {module}")
                res[module] = loaded_module.stix.build()
        return res

    def __check_module(self, module) -> bool:
        """
        Checks if the module is enabled for the stix output.

        :param module: module to check
        :type module: Module

        :return: True if the module is enabled
        :rtype: bool
        """
        return hasattr(module, "stix") and isinstance(module.stix, Bundled)
