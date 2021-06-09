from modules.server.hsts_base import Hsts_base
from utils.logger import Logger


class Hsts_not_set(Hsts_base):
    def _get_logger(self):
        return Logger("Hsts Not Set")

    # to override
    def _set_arguments(self):
        self._arguments = self._instance.HSTSSET

    # to override
    def _worker(self, results):
        return self._obtain_results(results)
