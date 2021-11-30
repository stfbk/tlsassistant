from modules.server.testssl_base import Testssl_base
from utils.mitigations import load_mitigation


class Pfs(Testssl_base):
    """
    Analysis of the pfs testssl results
    """

    # to override
    def _set_arguments(self):
        self._arguments = ["-f"]

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
            result["mitigation"] = load_mitigation("PFS")
        return result if condition else {}

    # to override
    def _worker(self, results):
        """
        The worker method, which runs the testssl command

        :param results: dict
        :return: dict
        :rtype: dict
        """
        return self._obtain_results(
            results,
            ["PFS_ciphers", "PFS_ECDHE_curves", "DH_groups", "pre_128cipher", "PFS"],
        )
