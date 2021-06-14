from modules.android.super_base import Super_base
from utils.logger import Logger


class Ssl_getinsecure_method(Super_base):
    def _get_logger(self):
        return Logger("SSL getInsecure method")

    # to override
    def _set_arguments(self):
        self._arguments = []

    # to override
    def _worker(self, results):
        return self._obtain_results(
            results, ["SSL getInsecure method"], ['highs']
        )
