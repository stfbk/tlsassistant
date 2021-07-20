from modules.server.hsts_base import Hsts_base
from utils.logger import Logger


class Hsts_preloading(Hsts_base):
    def _get_logger(self):
        return Logger("Hsts Not Preloaded")

    # to override
    def _set_arguments(self):
        self._arguments = self._instance.HSTSPRELOAD

    # to override
    def _worker(self, results):
        return self._obtain_results(results)
