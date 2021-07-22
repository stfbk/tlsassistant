from utils.validation import Validator
from utils.urls import url_domain, port_parse
from utils.mitigations import load_mitigation
from modules.server.wrappers.https_hsts import Https


class Hsts_base:
    """
    Hsts_base is the base class for all HSTS analysis.
    It is used to obtain the results of the analysis.
    """

    def __init__(self):
        self._input_dict = {}
        self._arguments = []
        self._instance = Https()
        self._output_dict = {}
        self._mitigations = {}
        self._set_arguments()
        self.__logging = self._get_logger()

    def _get_logger(self):
        """
        Returns the logger for the current class.
        Dummy function for the base class.

        :return: logger
        :rtype: Logger
        :raises: NotImplementedError
        """
        raise NotImplementedError("This method should be reimplemented!")

    def input(self, **kwargs):
        """
        Inputs the required data to the analysis.

        :param kwargs: data to be used for the analysis
        :type kwargs: dict

        :Keyword Arguments:
            * **hostname** (*str*) -- the hostname to be used for the analysis
            * **port** (*str*) -- the port to be used for the analysis
            * **type** (*str*) -- the type of analysis to be done
        """
        self._input_dict = kwargs

    def _set_mitigations(self, result: dict, key: str, condition: bool) -> dict:
        """
        Sets the mitigations for the analysis.

        :param result: the result dict
        :type result: dict
        :param key: the key to be used for the mitigations
        :type key: str
        :param condition: the condition to be used for the mitigations
        :type condition: bool
        :return: the result dict with the mitigations
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

        :param results: the results from the server
        :type results: dict
        :return: the results from the analysis
        :rtype: dict

        :raise NotImplementedError:
        """
        raise NotImplementedError("This method should be reimplemented!")

    def _get_var_name(self):
        """
        Returns the name of the variable to be used for the analysis.

        :return: the name of the variable
        :rtype: str
        """
        if self._arguments == self._instance.HTTPS:
            key = "HTTPS_NOT_ENFORCED"
        elif self._arguments == self._instance.HSTSSET:
            key = "HSTS_NOT_SET"
        elif self._arguments == self._instance.HSTSPRELOAD:
            key = "HSTS_NOT_PRELOADED"
        else:
            key = "SERVERINFO"
        return key

    def _obtain_results(self, results: bool or str):
        """
        Obtains the results from the analysis.

        :param results: the results from the analysis
        :type results: bool or str
        :return: the results from the analysis
        :rtype: dict
        """
        Validator(
            [
                (results, (bool, str)),  # bool if not serverinfo, else str
            ]
        )
        results = not results  # because of the logic of the mitigations
        conditioned_result = {self._input_dict["hostname"]: results}

        key = self._get_var_name()
        if self._arguments != self._instance.SERVERINFO and isinstance(results, bool):
            conditioned_result = self._set_mitigations(conditioned_result, key, results)
        out = {key: conditioned_result}
        return out

    def run(self, **kwargs):
        """
        Runs the analysis.

        :param kwargs: data to be used for the analysis
        :type kwargs: dict

        :Keyword Arguments:
            * **hostname** (*str*) -- the hostname to be used for the analysis
            * **port** (*str*) -- the port to be used for the analysis
            * **type** (*str*) -- the type of analysis to be done

        :return: the results from the analysis
        :rtype: dict
        """
        self.input(**kwargs)

        if "hostname" not in kwargs:
            raise AssertionError("Hostname is missing!")
        Validator([(self._input_dict["hostname"], str)])
        self._input_dict["hostname"] = url_domain(self._input_dict["hostname"])

        self.__logging.debug(
            f"Executing analysis in {self._input_dict['hostname']} with args {self._arguments}"
        )

        self._output_dict = self._worker(
            self._instance.run(
                hostname=self._input_dict["hostname"],
                port=self._input_dict["port"],
                type=self._arguments,
                force=True,
            )
        )
        return self.output()

    def output(self):
        """
        Returns the results from the analysis.

        :return: the results from the analysis
        :rtype: dict
        """
        return self._output_dict
