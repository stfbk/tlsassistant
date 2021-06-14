from modules.android.super_base import Super_base
from utils.logger import Logger


class Weak_algorithms(Super_base):
    def _get_logger(self):
        return Logger("Weak Algorithms")

    # to override
    def _set_arguments(self):
        self._arguments = []

    # to override
    def _worker(self, results):
        return self._obtain_results(
            results, ["Weak Algorithms"], ['highs']
        )
