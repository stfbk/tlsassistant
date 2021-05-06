from modules.server.testssl_base import Testssl_base


class Pfs(Testssl_base):

    # to override
    def _set_arguments(self):
        self._arguments = ["-f"]

    # to override
    def _worker(self, results):
        return self._obtain_results(
            results, ["PFS_ciphers", "PFS_ECDHE_curves", "DH_groups"]
        )

    def _set_mitigation(self):
        pass
        # todo : decide how to save mitigations
