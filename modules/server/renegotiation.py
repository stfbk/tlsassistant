from modules.server.testssl_base import Testssl_base


class Renegotiation(Testssl_base):

    # to override
    def _set_arguments(self):
        self._arguments = ["-R"]

    # to override
    def _worker(self, results):
        return self._obtain_results(results, ["secure_renego", "secure_client_renego"])

    def _set_mitigation(self):
        pass
        # todo : decide how to save mitigations
