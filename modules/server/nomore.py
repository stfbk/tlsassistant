from modules.server.testssl_base import Testssl_base


class Nomore(Testssl_base):

    # to override
    def _set_arguments(self):
        self._arguments = ["-4"]

    # to override
    def _worker(self, results):
        return self._obtain_results(results, ["RC4"])
