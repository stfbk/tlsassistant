from modules.configuration.configuration_base import Parse_configuration_protocols
from modules.server.tlsscanner_base import TLS_Scanner_base
from modules.stix.stix_base import Bundled
from utils.mitigations import load_mitigation


class Alpaca(TLS_Scanner_base):
    """
    Analysis of the poodle testssl results
    """

    stix = Bundled(mitigation_object=load_mitigation("ALPACA"))

    def _set_mitigations(self, result: dict, key: str, condition: bool) -> dict:
        """
        Sets the mitigations for the ALPACA results

        :param result: the result to set the mitigations in
        :type result: dict
        :param key: the key to set the mitigations for
        :type key: str
        :param condition: the condition to set the mitigations for
        :type condition: bool
        :return: the result with the mitigations
        :rtype: dict
        """

        condition = condition and key == "ALPACA"
        if condition:
            result["mitigation"] = load_mitigation("ALPACA")
            #  Handle the case if the the vulnerability is partially mitigated
            details = result["Details"]
            ext = ""
            if details["Strict SNI"] == "false":
                ext = "SNI"
            
            if details["Strict ALPN"] == "false":
                if ext != "":
                    ext += " and ALPN"  
                else:
                    ext = "ALPN" 
            result['mitigation']['Entry']['Mitigation']['Textual'] = result['mitigation']['Entry']['Mitigation']['Textual'].format(extensions = ext)

        return result if condition else {}

    # to override
    def _set_arguments(self):
        """
        Sets the arguments for the TLS-Scanner command
        """
        self._arguments = ["Sni","Alpn","Extension","ProtocolVersion","CipherSuite","Alpaca"]

    # to override
    def _worker(self, results):
        """
        The worker method, which runs the TLS-Scanner command

        :param results: dict
        :return: dict
        :rtype: dict
        """
        return self._obtain_results(results, ["ALPACA"])
