from modules.server.testssl_base import Testssl_base
from utils.mitigations import load_mitigation


class Renegotiation(Testssl_base):
    def _set_mitigations(self, result: dict, key: str, condition: bool) -> dict:
        condition = condition and (
            key == "secure_client_renego" or key == "secure_renego"
        )
        if condition:
            result["mitigation"] = load_mitigation("RENEGOTIATION")
        return result if condition else {}

    # to override
    def _set_arguments(self):
        self._arguments = ["-R"]

    # to override
    def _worker(self, results):
        return self._obtain_results(results, ["secure_renego", "secure_client_renego"])
