from modules.configuration.configuration_base import Parse_configuration_protocols
from modules.server.tlsscanner_base import TLS_Scanner_base
from modules.stix.stix_base import Bundled
from utils.mitigations import load_mitigation


class TLSPoodle(TLS_Scanner_base):
    """
    Analysis of the poodle TLS Scanner results
    """

    stix = Bundled(mitigation_object=load_mitigation("TLS POODLE"))

    def _set_mitigations(self, result: dict, key: str, condition: bool) -> dict:
        """
        Sets the mitigations for the poodle results

        :param result: the result to set the mitigations in
        :type result: dict
        :param key: the key to set the mitigations for
        :type key: str
        :param condition: the condition to set the mitigations for
        :type condition: bool
        :return: the result with the mitigations
        :rtype: dict
        """
        condition = condition and key == "TLS Poodle"
        if condition:
            result["mitigation"] = load_mitigation("TLS POODLE")
        
        return result if condition else {}

    # to override
    def _set_arguments(self):
        """
        Sets the arguments for the TLS-Scanner command
        """
        self._arguments = ["Sni","ProtocolVersion","CipherSuite","TlsPoodle"]

    # to override
    def _worker(self, results):
        """
        The worker method, which runs the TLS-Scanner command

        :param results: dict
        :return: dict
        :rtype: dict
        """
        return self._obtain_results(results, ["TLS Poodle"])
