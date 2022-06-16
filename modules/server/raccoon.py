from modules.configuration.configuration_base import Parse_configuration_protocols
from modules.server.tlsscanner_base import TLS_Scanner_base
from modules.stix.stix_base import Bundled
from utils.mitigations import load_mitigation
from utils.iana2openssl import iana2openssl

class Raccoon(TLS_Scanner_base):
    """
    Analysis of the Raccoon TLS-Scanner results
    """

    stix = Bundled(mitigation_object=load_mitigation("RACCOON"))

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
        condition = condition and key == "Raccoon"
        if condition:
            result["mitigation"] = load_mitigation("RACCOON")
            ciphers = []
            if result["vulnToDirectRaccoon"] == 'vulnerable':
                details = result["Details"]
                
                vulnerable_ciphers = []

                for cipher in details:
                    if details[cipher]['Result'] != "NOT VULNERABLE":
                        vulnerable_ciphers.append(cipher)

                vulnerable_ciphers = list(set(vulnerable_ciphers)) # Remove duplicates
                vulnerable_ciphers = [iana2openssl(cipher.split("-",1)[1]) for cipher in vulnerable_ciphers]
                
                for cipher in vulnerable_ciphers:
                    if cipher != "":
                        ciphers.append(cipher)
            
            if result["vulnToRaccoon"] == 'vulnerable':
                ciphers.append("kDHr") 
                ciphers.append("kDHd")
                ciphers.append("kDH")

            ciphers = ":!".join(ciphers)
            result['mitigation']['Entry']['Mitigation']['Apache'] = result['mitigation']['Entry']['Mitigation']['Apache'].format(vuln_ciphersuites = ciphers) 
            result['mitigation']['Entry']['Mitigation']['Nginx'] = result['mitigation']['Entry']['Mitigation']['Nginx'].format(vuln_ciphersuites = ciphers) 

        
        return result if condition else {}

    # to override
    def _set_arguments(self):
        """
        Sets the arguments for the TLS-Scanner command
        """
        self._arguments = ["Sni","Alpn","ProtocolVersion","CipherSuite","DirectRaccoon","DhValueAfter","RaccoonAttackAfter"]

    # to override
    def _worker(self, results):
        """
        The worker method, which runs the TLS-Scanner command

        :param results: dict
        :return: dict
        :rtype: dict
        """
        return self._obtain_results(results, ["Raccoon"])
