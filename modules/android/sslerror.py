from modules.android.mallodroid_base import Mallodroid_base
from utils.logger import Logger
from utils.mitigations import load_mitigation


class Ssl_error(Mallodroid_base):
    def _get_logger(self):
        return Logger("SSL Error")

    def _set_mitigations(self, result: dict, key: str, condition: bool) -> dict:
        if condition:
            result["mitigation"] = load_mitigation("SSL_Error",
                                                   raise_error=False)  # todo: we are missing a mitigation!
        return result if condition else {}

    # to override
    def _set_arguments(self):
        self._arguments = []

    # to override
    def _worker(self, results):
        return self._obtain_results(results, ['onreceivedsslerror'])
