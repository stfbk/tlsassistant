from modules.configuration.configuration_base import Parse_configuration_protocols
from modules.server.tlsscanner_base import TLS_Scanner_base
from modules.stix.stix_base import Bundled
from utils.mitigations import load_mitigation


class Alpaca(TLS_Scanner_base):
    """
    Analysis of the ALPACA TLS-Scanner results
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
            #  Handle the case if the the vulnerability is partially mitigated and provide a dynamic mitigation
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

            if "ALPN" or "SNI" in ext:
                result['mitigation']['Entry']['Mitigation']['Nginx'] = ""
            if "ALPN" in ext:
                result['mitigation']['Entry']['Mitigation']['Nginx'] = "To enable Strict ALPN in Nginx upgrade to version >=1.21.4. <br>"
            if "SNI" in ext:               
                result['mitigation']['Entry']['Mitigation']['Nginx'] += """
                To enable Strict SNI in Nginx: <br> 
                1. If you are using Nginx>=1.19.4 edit you configuration file usually located in <i>/etc/nginx/sites-enabled/default</i><br/> (if you changed your site conf name <i>/etc/nginx/sites-enabled/YOURSITECONFIGURATION</i>); to look like this:<br>
                <code>server {<br>
                    listen               443 ssl default_server;<br>
                    ssl_reject_handshake on;<br>
                }<br>
                <br>
                server {<br>
                    listen 443 ssl http2;<br>
                    listen [::]:443 ssl http2;<br>
                    server_name example.com;<br>
                    [...]<br>
                }<br>
                </code><br>
                2. If you are using nginx<1.19.4 follow <a href="https://blog.sion.moe/methods-to-prevent-leaking-websites-origin-server-ip-behind-cdn/">this guide</a><br>
                """
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
