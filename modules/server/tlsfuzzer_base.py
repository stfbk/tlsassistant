from modules.server.wrappers.tlsfuzzer import Tlsfuzzer
from utils.validation import Validator
from utils.urls import url_domain, port_parse
from utils.mitigations import load_mitigation
from utils.counter import count_occurrencies as grep
import logging


class Tlsfuzzer_base:
    """
    Interface for TLSFuzzer Vulnerability Analysis
    """

    def __init__(self):
        self._input_dict = {}
        self._arguments = []
        self._instance = Tlsfuzzer()
        self._output_dict = {}
        self._mitigations = {}
        self._set_arguments()
        self.__logging = self._get_logger()

    def _get_logger(self):
        """
        Logger for the class

        :raise NotImplementedError:
        """
        raise NotImplementedError("This method should be reimplemented!")

    def input(self, **kwargs):
        """
        Set input arguments for the analysis

        :param kwargs:
        :type kwargs: dict

        :Keyword Arguments:
            * *hostname* (``str``) -- Hostname to be tested
            * *force* (``bool``) -- Force the analysis
            * *port* (``str``) -- Port to be tested
            * *scripts* (``list``) -- List of scripts to be executed
        """
        self._input_dict = kwargs

    def _set_mitigations(self, result: dict, key: str, condition: bool) -> dict:
        """
        Set mitigations for the analysis

        :param result: results to be mitigated
        :type result: dict
        :param key: key to be mitigated
        :type key: str
        :param condition: condition to be mitigated
        :type condition: bool
        :return: mitigated results
        :rtype: dict
        """
        if condition:
            result["mitigation"] = load_mitigation(key, raise_error=False)
        return result if condition else {}

    # to override
    def _set_arguments(self):
        """
        Dummy method to be overridden

        :raise  NotImplementedError:
        """
        raise NotImplementedError("This method should be reimplemented!")

    # to override
    def _obtain_results(self, results: dict, keys: dict):
        """
        Obtain results from the analysis

        :param results: results to be processed
        :type results: dict
        :param keys: keys to be obtained
        :type keys: dict
        :return: processed results
        :rtype: dict
        """
        val = Validator([(results, dict), (keys, dict)])
        out = {}
        for script, list_of_checks in keys.items():
            assert script in results, f"Script {script} missing in results!"
            if grep("sanity", results[script]) == 2:
                # self.__logging.debug(results[script])
                set_mitigations = False
                for check, safe_value in list_of_checks.items():
                    if check != "MITIGATION":
                        out[check] = {}
                        string_to_grep = check
                        occurrencies = grep(string_to_grep, results[script])
                        if occurrencies > safe_value:
                            self.__logging.debug(
                                f"Found {occurrencies} occurrencies of {check}"
                                f" with script {script} (safe value is <={safe_value})"
                            )
                            set_mitigations = True
                if set_mitigations:
                    out[script] = {}
                    split = results[script].split("Test end", 1)
                    out[script]["code"] = (
                        split[1] if len(split) > 1 else results[script]
                    )
                    out = self._set_mitigations(out, list_of_checks["MITIGATION"], True)
            else:
                self.__logging.warning(
                    f"Results won't make sense for script {script}, sanity check failed."
                )
                self.__logging.info(f"Ignoring {script} analysis.\n")
        return out

    def _worker(self, results):
        """
        Dummy method to be overridden

        :param results: results to be processed
        :type results: dict

        :return: processed results
        :rtype: dict

        :raise  NotImplementedError:
        """
        raise NotImplementedError("This method should be reimplemented!")

    def run(self, **kwargs):
        """
        Run the analysis

        :param kwargs:
        :type kwargs: dict

        :Keyword Arguments:
            * *hostname* (``str``) -- Hostname to be tested
            * *port* (``str``) -- Port to be tested
            * *force* (``bool``) -- Force the analysis
            * *scripts* (``list``) -- List of scripts to be executed

        :return: results of the analysis
        :rtype: dict

        """
        self.input(**kwargs)

        if "hostname" not in kwargs:
            raise AssertionError("Hostname is missing!")
        if "port" not in kwargs:
            self._input_dict["port"] = "443"
        else:
            self._input_dict["port"] = port_parse(self._input_dict["port"])
        Validator(
            [(self._input_dict["hostname"], str), (self._input_dict["port"], str)]
        )
        self._input_dict["hostname"] = url_domain(self._input_dict["hostname"])

        logging.debug(
            f"Executing analysis in {self._input_dict['hostname']} in port {self._input_dict['port']} with scripts "
            f"{', '.join([s[0] for s in self._arguments])}"
        )

        self._output_dict = self._worker(
            self._instance.run(
                hostname=self._input_dict["hostname"],
                port=self._input_dict["port"],
                scripts=self._arguments,
                force=self._input_dict.get("force", False),
            )
        )
        return self.output()

    def output(self):
        """
        Obtain results of the analysis

        :return: results of the analysis
        :rtype: dict
        """
        return self._output_dict
