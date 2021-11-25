from modules.server.testssl_base import Testssl_base
from utils.mitigations import load_mitigation


class Logjam(Testssl_base):
    """
    Analysis of the logjam testssl results
    """

    # to override
    def _set_arguments(self):
        """
        Sets the arguments for the testssl command
        """
        self._arguments = ["-J"]

    def _set_mitigations(self, result: dict, key: str, condition: bool) -> dict:
        """
        Override the _set_mitigations method to add the logjam results

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
            result["mitigation"] = load_mitigation("LOGJAM")
        return result if condition else {}

    # to override
    def _worker(self, results):
        """
        The worker method, which runs the testssl command

        :param results: dict
        :return: dict
        :rtype: dict
        """
        return self._obtain_results(results, ["LOGJAM", "LOGJAM-common_primes"])
