from modules.server.testssl_base import Testssl_base
from utils.mitigations import load_mitigation


class Drown(Testssl_base):
    def _set_mitigations(self, result: dict, key: str, condition: bool) -> dict:
        condition = condition and (key == "DROWN" or key == "DROWN_hint")
        if condition:
            result["mitigation"] = load_mitigation("DROWN")
        return result if condition else {}

    # to override
    def _set_arguments(self):
        self._arguments = ["-D"]

    # to override
    def _worker(self, results):
        return self._obtain_results(results, ["DROWN", "DROWN_hint"])
