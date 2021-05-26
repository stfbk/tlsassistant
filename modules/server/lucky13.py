from modules.server.testssl_base import Testssl_base


class Lucky13(Testssl_base):

    # to override
    def _set_arguments(self):
        self._arguments = ["-L"]

    # to override
    def _worker(self, results):
        return self._obtain_results(results, ["LUCKY13"])
