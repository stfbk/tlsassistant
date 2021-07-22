from modules.server.testssl_base import Testssl_base


class Pfs(Testssl_base):
    """
    Analysis of the pfs testssl results
    """

    # to override
    def _set_arguments(self):
        self._arguments = ["-f"]

    # to override
    def _worker(self, results):
        """
        The worker method, which runs the testssl command

        :param results: dict
        :return: dict
        :rtype: dict
        """
        return self._obtain_results(
            results, ["PFS_ciphers", "PFS_ECDHE_curves", "DH_groups"]
        )
