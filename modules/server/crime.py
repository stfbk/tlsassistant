from modules.server.testssl_base import Testssl_base
import logging


class Crime(Testssl_base):

    # to override
    def _set_arguments(self):
        self._arguments = ["-C"]

    # to override
    def _worker(self, results):
        return self._obtain_results(results, ["CRIME_TLS"])

    def _set_mitigation(self):
        pass
        # todo : decide how to save mitigations
