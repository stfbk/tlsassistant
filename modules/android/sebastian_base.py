from modules.android.wrappers.sebastian import Sebastian
from utils.validation import Validator
from utils.mitigations import load_mitigation


class Sebastian_base:
    """
    Interface class for SEBASTiAn vulnerability detection.
    """

    def __init__(self):
        self._input_dict = {}
        self._arguments = []
        self._instance = Sebastian()
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
        Inputs the arguments for the SEBASTiAn instance.

        :param kwargs:
        :Keyword Arguments:
            - path (str): Path to the apk file.
            - args (list): List of arguments to be passed to the SEBASTiAn instance.
            - force (bool): Force the execution of the SEBASTiAn instance.
        """
        self._input_dict = kwargs

    def _set_mitigations(self, result: dict, key: str, condition: bool) -> dict:
        """
        Sets the mitigations for the SEBASTiAn instance.

        :param result: The result of the SEBASTiAn instance.
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
        Versatile method to obtain the results from the SEBASTiAn instance.

        :param results: The result of the SEBASTiAn instance.
        :param keys: The keys to search for.
        :return: The result of the SEBASTiAn instance contextual to the key.
        :rtype: dict

        """
        val = Validator([(results, dict), (keys, list)])
        out = {}

        for key in keys:
            val.string(key)
            for result in results:
                vulnerabilities = results.get("vulnerabilities", {}) 
                for vulnerability in vulnerabilities:
                    if vulnerability.get("id") == key:
                        dict_code = {item['full_path']: item for item in vulnerability.get("code")}
                        mit = self._set_mitigations(dict_code,key,True)
                        if key not in out:
                            out[key] = []
                        if mit:
                            out[key].append(mit)
                if result == "errors":
                    out["errors"] = results["errors"]

        return out

    def run(self, **kwargs):
        """
        Runs the SEBASTiAn module.

        :param kwargs:
        :Keyword Arguments:
            - path (str): Path to the apk file.
            - args (list): List of arguments to be passed to the SEBASTiAn instance.
            - force (bool): Force the execution of the SEBASTiAn instance.
        """
        self.input(**kwargs)
        if "path" not in kwargs:
            raise AssertionError("path is missing!")
        Validator([(self._input_dict["path"], str)])
        self._input_dict["path"] = self._input_dict["path"]
        self._output_dict = self._worker(
            self._instance.run(
                path=self._input_dict["path"],
                args=self._arguments,
                force=self._input_dict.get("force", False),
            )
        )
        return self.output()

    def output(self):
        """
        Returns the output of the SEBASTiAn module.

        :return: The output of the SEBASTiAn module.
        :rtype: dict
        """
        return self._output_dict
    
