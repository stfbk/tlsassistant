from modules.server.testssl_base import Testssl_base
from modules.stix.stix_base import Bundled
from utils.mitigations import load_mitigation


class Renegotiation(Testssl_base):
    """
    Analysis of the renego testssl results
    """

    stix = Bundled(mitigation_object=load_mitigation("RENEGOTIATION"))

    def _set_mitigations(self, result: dict, key: str, condition: bool) -> dict:
        """
        Sets the mitigations for the result

        :param result: the result of the testssl command
        :type result: dict
        :param key: the key of the result
        :type key: str
        :param condition: the condition to set
        :type condition: bool
        :return: the result dict
        :rtype: dict
        """
        condition = condition and (
            key == "secure_client_renego" or key == "secure_renego"
        )
        if condition:
            result["mitigation"] = load_mitigation("RENEGOTIATION")
        return result if condition else {}

    # to override
    def _set_arguments(self):
        """
        Sets the arguments for the testssl command
        """
        self._arguments = ["-R"]

    # to override
    def _worker(self, results):
        """
        The worker method, which runs the testssl command

        :param results: dict
        :return: dict
        :rtype: dict
        """
        return self._obtain_results(results, ["secure_renego", "secure_client_renego"])
