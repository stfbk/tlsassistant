from utils.validation import Validator


class Stixer:
    def __init__(self, modules):
        Validator([(modules, dict)])
        self.__exec_stix(modules)

    def __is_stix_enabled(self, module) -> bool:
        """
        Checks if the module is enabled for the stix processing.

        :param module: module to check
        :type module: Module
        :return: True if the module is enabled
        :rtype: bool
        """
        return hasattr(module, "stix") and isinstance(module.stix, Bundle)

    def __check_stix(self, modules) -> tuple:
        for module_name, module in modules.items():
            if self.__is_stix_enabled(module):
                yield module_name, module

    def __exec_stix(self, modules):
        for module_name, module in self.__check_stix(modules):

            # TODO: implement logic
            pass
