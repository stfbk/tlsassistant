from modules.server.testssl_base import Testssl_base


class Beast(Testssl_base):

    # to override
    def _set_arguments(self):
        self._arguments = ["-A"]

    # to override
    def _worker(self, results):
        return self._obtain_results(results, ["BEAST"])

    def _set_mitigation(self):
        pass
        # todo : decide how to save mitigations
