from modules.android.mallodroid_base import Mallodroid_base
from utils.logger import Logger
from utils.mitigations import load_mitigation


class Ssl_error(Mallodroid_base):
    """
    Checks if the application got any ssl error.
    """

    def _get_logger(self):
        """
        Gets the module's logger instance.
        :return: the logger instance.
        :rtype: Logger
        """
        return Logger("SSL Error")

    def _set_mitigations(self, result: dict, key: str, condition: bool) -> dict:
        """
        Sets mitigations based on the result.

        :param result: the result to analyze.
        :param key: the key to analyze.
        :param condition: the condition to analyze.
        :return: the result with the new mitigations.
        :rtype: dict
        """
        if condition:
            result["mitigation"] = load_mitigation(
                "SSL_Error", raise_error=False
            )  # todo: we are missing a mitigation!
        return result if condition else {}

    # to override
    def _set_arguments(self):
        """
        Sets the module arguments.
        """
        self._arguments = []

    # to override
    def _worker(self, results):
        """
        The module's worker.

        :param results: the current module's results.
        :type results: dict
        :return: the module's results updated with the analysis.
        :rtype: dict
        """
        return self._obtain_results(results, ["onreceivedsslerror"])
