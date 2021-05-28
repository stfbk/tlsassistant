from modules.server.testssl_base import Testssl_base
from utils.mitigations import load_mitigation


class Poodle(Testssl_base):
    def _set_mitigations(self, result: dict, key: str, condition: bool) -> dict:
        condition = condition and (key == "POODLE_SSL" or key == "fallback_SCSV")
        if condition:
            result["mitigation"] = load_mitigation("POODLE")
        return result if condition else {}

    # to override
    def _set_arguments(self):
        self._arguments = ["-O"]

    # to override
    def _worker(self, results):
        return self._obtain_results(results, ["POODLE_SSL", "fallback_SCSV"])
