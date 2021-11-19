from modules.configuration.configuration_base import Parse_configuration_checks_redirect
from modules.server.hsts_base import Hsts_base
from utils.logger import Logger
from utils.mitigations import load_mitigation


class Https_enforced(Hsts_base):
    """
    This function checks if the server is configured to enforce HTTPS.
    """

    conf = Parse_configuration_checks_redirect()

    def _get_logger(self):
        """
        Get logger instance

        :return: Logger instance
        :rtype: Logger
        """
        return Logger("Https Not Enforced")

    # to override
    def _set_arguments(self):
        """
        This function sets the arguments to be passed to the check function.
        """
        self._arguments = self._instance.HTTPS

    def _set_mitigations(self, result: dict, key: str, condition: bool) -> dict:
        """
        Sets the mitigations for the analysis.

        :param result: the result dict
        :type result: dict
        :param key: the key to be used for the mitigations
        :type key: str
        :param condition: the condition to be used for the mitigations
        :type condition: bool
        :return: the result dict with the mitigations
        :rtype: dict
        """
        if condition:
            result["mitigation"] = load_mitigation(
                "HTTPS_NOT_ENFORCED", raise_error=False
            )  # todo: remove, debug until we have all mitigations
        return result if condition else {}

    # to override
    def _worker(self, results):
        """
        This function checks if the server is configured to enforce HTTPS.

        :param results: results of the request
        :type results: dict
        :return: refined results of the request
        :rtype: dict
        """
        return self._obtain_results(results)
