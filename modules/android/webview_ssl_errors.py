from modules.android.super_base import Super_base
from modules.stix.stix_base import Bundled
from utils.logger import Logger
from utils.mitigations import load_mitigation


class Webview_ssl_errors(Super_base):
    """
    Check if the WebView ignores SSL Errors.
    """

    stix = Bundled(mitigation_object=load_mitigation("WEBVIEW_IGNORES_SSL_ERRORS"))

    def _get_logger(self):
        """
        Get the module logger named after the module.

        :return: logger
        :rtype: Logger
        """
        return Logger("WebView Ignores SSL Errors")

    # to override
    def _set_arguments(self):
        """
        Set the module arguments.
        """
        self._arguments = []

    # to override
    def _worker(self, results):
        """
        Worker for the module.

        :param results: results from the module
        :type results: dict
        :return: results
        :rtype: dict
        """
        return self._obtain_results(
            results, ["WebView ignores SSL errors"], ["criticals"]
        )
