from modules.configuration.configuration_base import Parse_configuration_protocols
from modules.server.testssl_base import Testssl_base
from utils.mitigations import load_mitigation


class Drown(Testssl_base):
    conf = Parse_configuration_protocols(openssl="1.0.2g", protocols={"SSLv2": "-"})

    """
    Analysis of the drown testssl results
    """

    def _set_mitigations(self, result: dict, key: str, condition: bool) -> dict:
        """
        Override of the _set_mitigations method, to add the mitigations for the drown testssl results

        :param result: the result to be mitigated
        :type result: dict
        :param key: the key of the result to be mitigated
        :type key: str
        :param condition: the condition to be mitigated
        :type condition: bool
        :return: the mitigated result
        :rtype: dict
        """
        condition = condition and (key == "DROWN" or key == "DROWN_hint")
        if condition:
            result["mitigation"] = load_mitigation("DROWN")
        return result if condition else {}

    # to override
    def _set_arguments(self):
        """
        Sets the arguments for the testssl command
        """
        self._arguments = ["-D"]

    # to override
    def _worker(self, results):
        """
        The worker method, which runs the testssl command

        :param results: dict
        :return: dict
        :rtype: dict
        """
        return self._obtain_results(results, ["DROWN", "DROWN_hint"])
