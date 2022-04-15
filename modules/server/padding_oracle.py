from modules.configuration.configuration_base import Parse_configuration_protocols
from modules.server.tlsscanner_base import TLS_Scanner_base
from modules.stix.stix_base import Bundled
from utils.mitigations import load_mitigation
from utils.iana2openssl import iana2openssl

class PaddingOracle(TLS_Scanner_base):
    """
    Analysis of the Padding Oracle TLS Scanner results
    """

    conf = Parse_configuration_protocols(openssl="3.0.0", protocols={"SSLv3": "-"}) # FIXX?
    stix = Bundled(mitigation_object=load_mitigation("PADDING ORACLE")) # FIX

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
        condition = condition and key == "Padding Oracle"
        if condition:
            result["mitigation"] = load_mitigation("PADDING ORACLE")
            # Add vulnerable ciphers to the mitigation 
            
            details = result['Details']
            vulnerable_ciphers = []
            for cipher in details:
                if details[cipher]['Result'] != "NOT VULNERABLE":
                    vulnerable_ciphers.append(cipher)
            
            vulnerable_ciphers = list(set(vulnerable_ciphers)) # Remove duplicates

            vulnerable_ciphers = [iana2openssl(cipher.split("-",1)[1]) for cipher in vulnerable_ciphers]
            ciphers = ":!".join(vulnerable_ciphers)
            # TODO: Check for key error
            result['mitigation']['Entry']['Mitigation']['Apache'] = result['mitigation']['Entry']['Mitigation']['Apache'].format(vuln_ciphersuites = ciphers) 
            result['mitigation']['Entry']['Mitigation']['Nginx'] = result['mitigation']['Entry']['Mitigation']['Nginx'].format(vuln_ciphersuites = ciphers) 
            
        return result if condition else {}

    # to override
    def _set_arguments(self):
        """
        Sets the arguments for the testssl command
        """
        self._arguments = ["Sni","ProtocolVersion","CipherSuite","PaddingOracle","PaddingOracleIdentificationAfter"]

    # to override
    def _worker(self, results):
        """
        The worker method, which runs the testssl command

        :param results: dict
        :return: dict
        :rtype: dict
        """
        return self._obtain_results(results, ["Padding Oracle"])
