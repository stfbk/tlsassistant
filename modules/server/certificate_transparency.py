from modules.server.testssl_base import Testssl_base
import logging


class Certificate_transparency(Testssl_base):

    # to override
    def _set_arguments(self):
        self._arguments = ["-S"]

    # to override
    def _worker(self, results):
        return self._obtain_results(results, ["certificate_transparency"])
