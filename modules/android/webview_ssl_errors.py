from modules.android.super_base import Super_base
from utils.logger import Logger


class Webview_ssl_errors(Super_base):
    def _get_logger(self):
        return Logger("WebView Ignores SSL Errors")

    # to override
    def _set_arguments(self):
        self._arguments = []

    # to override
    def _worker(self, results):
        return self._obtain_results(
            results, ["WebView ignores SSL errors"], ["criticals"]
        )
