from modules.server.testssl_base import Testssl_base
from utils.mitigations import load_mitigation


class Three_shake(Testssl_base):
    def _set_mitigations(self, result: dict, key: str, condition: bool) -> dict:
        condition = 'extended master secret/#23' not in result['finding'] if 'finding' in result else False
        if condition:
            result["mitigation"] = load_mitigation("3SHAKE")
        return result if condition else {}

    # to override
    def _set_arguments(self):
        self._arguments = ["-S"]

    # to override
    def _worker(self, results):
        return self._obtain_results(results, ['TLS_extensions'])
