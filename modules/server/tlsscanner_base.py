import logging
from collections import defaultdict

from modules.server.wrappers.tlsscanner import TLS_Scanner
from utils.mitigations import load_mitigation
from utils.urls import port_parse, url_domain
from utils.validation import Validator


class TLS_Scanner_base:
    """
    TLS-Scanner is a tool created by the Chair for Network and Data Security 
    from the Ruhr-University Bochum to assist pentesters and security researchers 
    in the evaluation of TLS Server configurations.

    This is a base class for the different vulnerabilities found by TLS-Scanner.jar.
    """

    def __init__(self):
        self._input_dict = {}
        self._arguments = []
        self._instance = TLS_Scanner()
        self._output_dict = {}
        self._mitigations = {}
        self._set_arguments()

    def input(self, **kwargs):
        """
        This method is used to set the input parameters for the analysis.

        :param kwargs:
        :type kwargs: dict

        :Keyword Arguments:
            * *hostname* (``str``) -- Hostname to be analyzed.
            * *force* (``bool``) -- Force the analysis.
            * *port* (``str``) -- Port to be analyzed.
            * *keys* (``list``) -- List of keys to be analyzed.
        """
        self._input_dict = kwargs

    def _set_mitigations(self, result: dict, key: str, condition: bool) -> dict:
        """
        This method is used to set the mitigations for the different vulnerabilities.

        :param result: The result of the analysis.
        :type result: dict
        :param key: The key of the result.
        :type key: str
        :param condition: If the condition is met.
        :type condition: bool
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
        Dummy method to be overridden

        :raise  NotImplementedError:
        """
        raise NotImplementedError("This method should be reimplemented!")

    # to override
    def _worker(self, results):
        """
        Dummy method to be overridden

        :raise  NotImplementedError:
        :param results: results of the analysis.
        :type results: dict

        :return: The results of the analysis.
        :rtype: dict
        """
        raise NotImplementedError("This method should be reimplemented!")

    def _obtain_results(self, results: dict, keys: list):
        """
        This method is used to obtain the results of the analysis.

        :param results: The results of the analysis.
        :type results: dict
        :param keys: The keys of the results.
        :type keys: list
        :return: The results of the analysis.
        :rtype: dict
        """
        val = Validator([(results, dict), (keys, list)])
        out = defaultdict(dict)
        
        for hostname in results:
            for key in keys:
                not_in_this=["error","not tested yet","could not test (not vulnerable)","true","not vulnerable"]
                
                condition = results[hostname][key]['Result'] not in not_in_this if "Result" in results[hostname][key] else False 

                conditioned_result = self._set_mitigations(
                    results[hostname][key], key, condition
                )

                if conditioned_result:
                    out[hostname][key] = conditioned_result
        
        return out

    def run(self, **kwargs):
        """
        This method is used to run the analysis.

        :param kwargs:
        :type kwargs: dict

        :Keyword Arguments:
            * *hostname* (``str``) -- Hostname to be analyzed.
            * *port* (``str``) -- Port to be analyzed.
            * *force* (``bool``) -- Force the analysis.
            * *keys* (``list``) -- List of keys to be analyzed.

        :return: The results of the analysis.
        :rtype: dict
        """
        self.input(**kwargs)

        if "hostname" not in kwargs:
            raise AssertionError("Hostname is missing!")
        Validator([(self._input_dict["hostname"], str)])
        self._input_dict["hostname"] = url_domain(self._input_dict["hostname"])
        if "port" in self._input_dict:
            self._input_dict[
                "hostname"
            ] = f'{self._input_dict["hostname"]}:{port_parse(self._input_dict["port"])}'

        logging.debug(
            f"Executing analysis in {self._input_dict['hostname']} with args {self._arguments}"
        )
        self._output_dict = self._worker(
            self._instance.run(
                hostname=self._input_dict["hostname"],
                args=self._arguments,
                force=self._input_dict.get("force", False),
            )
        )
        return self.output()

    def output(self):
        """
        This method is used to output the results of the analysis.

        :return: The results of the analysis.
        :rtype: dict
        """
        return self._output_dict.copy()
