from modules.server.testssl_base import Testssl_base


class Freak(Testssl_base):

    # to override
    def _set_arguments(self):
        self._arguments = ["-F"]

    # to override
    def _worker(self, results):
        return self._obtain_results(results, ["FREAK"])
