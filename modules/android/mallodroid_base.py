from modules.android.wrappers.mallodroid import Mallodroid
from utils.validation import Validator
from utils.mitigations import load_mitigation
import logging


class Mallodroid_base:
    """
    Interface class for Mallodroid vulnerability detection.
    """

    def __init__(self):
        self._input_dict = {}
        self._arguments = []
        self._instance = Mallodroid()
        self._output_dict = {}
        self._mitigations = {}
        self._set_arguments()
        self.__logging = self._get_logger()

    def _get_logger(self):
        """
        Returns a logger instance.
        """
        raise NotImplementedError("This method should be reimplemented!")

    def input(self, **kwargs):
        """
        Inputs the arguments for the Mallodroid instance.

        :param kwargs:
        :Keyword Arguments:
            - path (str): Path to the apk file.
            - args (list): List of arguments to be passed to the Mallodroid instance.
            - force (bool): Force the execution of the Mallodroid instance.
        """
        self._input_dict = kwargs

    def _set_mitigations(self, result: dict, key: str, condition: bool) -> dict:
        """
        Sets the mitigations for the Mallodroid instance.

        :param result: The result of the Mallodroid instance.
        :param key: The key to search for vulnerability in the result.
        :param condition: The condition to be mitigated.
        :return: The result with mitigation.
        :rtype: dict

        """
        if condition:
            result["mitigation"] = load_mitigation(
                key, raise_error=False
            )  # todo: remove, debug until we have all mitigations
        return result if condition else {}

    # to override
    def _set_arguments(self):
        """
        Dummy method to be overridden.

        :raise NotImplementedError:
        """
        raise NotImplementedError("This method should be reimplemented!")

    # to override
    def _worker(self, results):
        """
        Dummy method to be overridden.

        :raise NotImplementedError:
        """
        raise NotImplementedError("This method should be reimplemented!")

    def _obtain_results(self, results: dict, keys: list):
        """
        Versatile method to obtain the results from the Mallodroid instance.

        :param results: The result of the Mallodroid instance.
        :param keys: The keys to search for.
        :return: The result of the Mallodroid instance contextual to the key.
        :rtype: dict

        """
        val = Validator([(results, dict), (keys, list)])
        out = {}

        for key in keys:
            val.string(key)
            for value in results[key]:
                if "empty" in value:
                    single = self._set_mitigations(value, key, value["empty"])
                    # removing useless information atm
                    single.pop("xref", None)
                    single.pop("java_b64", None)

                    if key not in out:
                        out[key] = []
                    if single:
                        out[key].append(single)
        return out

    def run(self, **kwargs):
        """
        Runs the Mallodroid module.

        :param kwargs:
        :Keyword Arguments:
            - path (str): Path to the apk file.
            - args (list): List of arguments to be passed to the Mallodroid instance.
            - force (bool): Force the execution of the Mallodroid instance.
        """
        self.input(**kwargs)

        if "path" not in kwargs:
            raise AssertionError("path is missing!")
        Validator([(self._input_dict["path"], str)])
        self._input_dict["path"] = self._input_dict["path"]
        self._output_dict = self._worker(
            self._instance.run(path=self._input_dict["path"], args=self._arguments, force = self._input_dict.get("force", False))
        )
        return self.output()

    def output(self):
        """
        Returns the output of the Mallodroid module.

        :return: The output of the Mallodroid module.
        :rtype: dict
        """
        return self._output_dict
