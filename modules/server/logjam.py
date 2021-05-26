from modules.server.testssl_base import Testssl_base


class Logjam(Testssl_base):

    # to override
    def _set_arguments(self):
        self._arguments = ["-J"]

    # to override
    def _worker(self, results):
        return self._obtain_results(results, ["LOGJAM", "LOGJAM-common_primes"])
