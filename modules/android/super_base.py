from modules.android.wrappers.super import Super
from utils.validation import Validator
from utils.mitigations import load_mitigation


class Super_base:
    """
    Interface for SUPERAndroidAnalyzer vulnerability detection.
    """

    def __init__(self):
        self._input_dict = {}
        self._arguments = []
        self._instance = Super()
        self._output_dict = {}
        self._mitigations = {}
        self._set_arguments()
        self.__logging = self._get_logger()

    def _get_logger(self):
        """
        Returns a logger instance.
        Dummy method to be overridden.

        :return: logger instance
        :rtype: Logger
        :raise: NotImplementedError
        """
        raise NotImplementedError("This method should be reimplemented!")

    def input(self, **kwargs):
        """
        Receives the input arguments from the user.

        :param kwargs: input arguments
        :Keyword Arguments:
            * *path* (``str``) -- path to the file
            * *args* (``list``) -- list of arguments
            * *force* (``bool``) -- force the analysis
        """
        self._input_dict = kwargs

    def _set_mitigations(self, result: dict, key: str, condition: bool) -> dict:
        """
        Sets the mitigations for the given result.

        :param result: result to be mitigated
        :param key: name of the result
        :param condition: condition to be mitigated
        :return: the result with mitigation
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

        :raise: NotImplementedError
        """
        raise NotImplementedError("This method should be reimplemented!")

    # to override
    def _worker(self, results):
        """
        Dummy method to be overridden.

        :raise: NotImplementedError
        """
        raise NotImplementedError("This method should be reimplemented!")

    def _obtain_results(self, results: dict, keys: list, types: list):
        """
        Versatile method to obtain the results from the results dictionary.

        :param results: results dictionary
        :param keys: keys to be obtained
        :param types: types of the keys
        :return: the obtained results
        :rtype: dict
        """
        val = Validator([(results, dict), (keys, list), (types, list)])
        out = {}

        for key in keys:
            val.string(key)
            for type_ in types:
                val.string(type_)
                for value in results[type_]:
                    if value["name"].lower() == key.lower():
                        single = self._set_mitigations(value, value["name"], True)
                        if key not in out:
                            out[key] = []
                        if single:
                            out[key].append(single)
        return out

    def run(self, **kwargs):
        """
        Runs the analysis.

        :param kwargs: input arguments
        :Keyword Arguments:
            * *path* (``str``) -- path to the file
            * *args* (``list``) -- list of arguments
            * *force* (``bool``) -- force the analysis
        :return: results
        :rtype: dict
        :raise AssertionError: if the input arguments are not valid
        """
        self.input(**kwargs)

        if "path" not in kwargs:
            raise AssertionError("path is missing!")
        Validator([(self._input_dict["path"], str)])
        self._input_dict["path"] = self._input_dict["path"]
        self._output_dict = self._worker(
            self._instance.run(path=self._input_dict["path"], args=self._arguments,force=self._input_dict.get("force",False))
        )
        return self.output()

    def output(self):
        return self._output_dict
