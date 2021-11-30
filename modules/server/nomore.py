from modules.configuration.configuration_base import Parse_configuration_ciphers
from modules.server.testssl_base import Testssl_base
from modules.stix.stix_base import Bundled
from utils.mitigations import load_mitigation


class Nomore(Testssl_base):
    """
    Analysis of the nomore testssl results
    """

    conf = Parse_configuration_ciphers(openssl="1.1.0", ciphers=["RC4"])
    stix = Bundled(mitigation_object=load_mitigation("NOMORE"))

    def _set_mitigations(self, result: dict, key: str, condition: bool) -> dict:
        """
        Sets the mitigations for the given result

        :param result: the result to set the mitigations for
        :type result: dict
        :param key: the key of the result
        :type key: str
        :param condition: the condition to set the mitigations for
        :type condition: bool
        :return: the mitigations for the given result
        :rtype: dict
        """
        if condition:
            result["mitigation"] = load_mitigation("NOMORE")
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
