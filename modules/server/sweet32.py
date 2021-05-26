from modules.server.testssl_base import Testssl_base


class Sweet32(Testssl_base):

    # to override
    def _set_arguments(self):
        self._arguments = ["-W"]

    # to override
    def _worker(self, results):
        return self._obtain_results(results, ["SWEET32"])
