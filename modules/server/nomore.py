from modules.server.testssl_base import Testssl_base
from utils.mitigations import load_mitigation


class Nomore(Testssl_base):

    def _set_mitigations(self, result: dict, key: str, condition: bool) -> dict:
        if condition:
            result["mitigation"] = load_mitigation("NOMORE")
        return result if condition else {}
    # to override
    def _set_arguments(self):
        self._arguments = ["-4"]

    # to override
    def _worker(self, results):
        return self._obtain_results(results, ["RC4"])
