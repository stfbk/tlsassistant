from modules.server.testssl_base import Testssl_base
from modules.stix.stix_base import Bundled
from utils.mitigations import load_mitigation


class Three_shake(Testssl_base):
    """
    Analysis of the 3shake testssl results
    """

    stix = Bundled(mitigation_object=load_mitigation("3SHAKE"))

    def __init__(self):
        super().__init__()
        self._versions = {}

    def _tls_versions(self, results: dict) -> dict:
        for ip in results:
            if self._versions.get(ip) is None:
                self._versions[ip] = {}
            for key in ["SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3"]:
                self._versions[ip][key] = results[ip].get(key, {"finding": "not offered"})[
                    "finding"].startswith("offered")

    def _set_mitigations(self, result: dict, key: str, condition: bool) -> dict:
        """
        Sets the mitigations for the 3shake testssl results

        :param result: The result dict to set the mitigations
        :type result: dict
        :param key: The key to set the mitigations
        :type key: str
        :param condition: The condition to set the mitigations
        :type condition: bool
        :return: The mitigated result
        :rtype: dict
        """
        condition = (
            "extended master secret/#23" not in result["finding"]
            if "finding" in result
            else False
        )
        if condition and any(self._versions.get(self.currently_analysed_ip, {}).get(key) for key in ["SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2"]):
            result["mitigation"] = load_mitigation("3SHAKE")
        return result if condition else {}

    # to override
    def _set_arguments(self):
        """
        Sets the arguments for the testssl command
        """
        self._arguments = ["-S", "-p"]

    # to override
    def _worker(self, results):
        """
        The worker method, which runs the testssl command

        :param results: dict
        :return: dict
        :rtype: dict
        """
        self._tls_versions(results)
        return self._obtain_results(results, ["TLS_extensions"])
