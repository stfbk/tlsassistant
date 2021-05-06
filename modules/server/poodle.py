from modules.server.testssl_base import Testssl_base


class Poodle(Testssl_base):

    # to override
    def _set_arguments(self):
        self._arguments = ["-O"]

    # to override
    def _worker(self, results):
        return self._obtain_results(results, ["POODLE_SSL", "fallback_SCSV"])

    def _set_mitigation(self):
        pass
        # todo : decide how to save mitigations
