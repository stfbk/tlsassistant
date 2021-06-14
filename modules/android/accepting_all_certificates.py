from modules.android.super_base import Super_base
from utils.logger import Logger


class Accepting_all_certificates(Super_base):
    def _get_logger(self):
        return Logger("Accepting all SSL certificates")

    # to override
    def _set_arguments(self):
        self._arguments = []

    # to override
    def _worker(self, results):
        return self._obtain_results(
            results, ["Accepting all SSL certificates"], ["criticals"]
        )
