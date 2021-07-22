from modules.configuration.configuration_base import Parse_configuration_checks_redirect
from modules.server.hsts_base import Hsts_base
from utils.logger import Logger


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
