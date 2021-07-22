from modules.configuration.configuration_base import Parse_configuration_ciphers
from modules.server.testssl_base import Testssl_base
from utils.mitigations import load_mitigation


class Mitzvah(Testssl_base):
    """
    Analysis of the mitzvah testssl results
    """

    conf = Parse_configuration_ciphers(openssl="1.1.0", ciphers=["RC4"])

    def _set_mitigations(self, result: dict, key: str, condition: bool) -> dict:
        """
        Override the _set_mitigations method to add the mitzvah results

        :param result: the results of the testssl command
        :type result: dict
        :param key: the key of the result
        :type key: str
        :param condition: the condition to check
        :type condition: bool
        :return: the result with the mitzvah results
        :rtype: dict
        """
        if condition:
            result["mitigation"] = load_mitigation("MITZVAH")
        return result if condition else {}

    # to override
    def _set_arguments(self):
        """
        Sets the arguments for the testssl command
        """
        self._arguments = ["-4"]

    # to override
    def _worker(self, results):
        """
        The worker method, which runs the testssl command

        :param results: dict
        :return: dict
        :rtype: dict
        """
        return self._obtain_results(results, ["RC4"])
