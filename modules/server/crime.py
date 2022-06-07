from modules.configuration.configuration_base import (
    Parse_configuration_checks_compression,
)
from modules.server.testssl_base import Testssl_base

from modules.stix.stix_base import Bundled
from utils.mitigations import load_mitigation


class Crime(Testssl_base):
    conf = Parse_configuration_checks_compression(openssl="1.1.0")
    stix = Bundled(mitigation_object=load_mitigation("CRIME"))
    """
    Analysis of the crime testssl results
    """

    # to override
    def _set_arguments(self):
        """
        Sets the arguments for the testssl command
        """
        self._arguments = ["-C"]
        
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
                "CRIME", raise_error=False
            )  # todo: remove, debug until we have all mitigations
        return result if condition else {}

    # to override
    def _worker(self, results):
        """
        The worker method, which runs the testssl command

        :param results: dict
        :return: dict
        :rtype: dict
        """
        return self._obtain_results(results, ["CRIME_TLS"])
