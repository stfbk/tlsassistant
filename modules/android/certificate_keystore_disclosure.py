from modules.android.super_base import Super_base
from utils.logger import Logger


class Certificate_keystore_disclosure(Super_base):
    def _get_logger(self):
        return Logger("Certificate or Keystore disclosure")

    # to override
    def _set_arguments(self):
        self._arguments = []

    # to override
    def _worker(self, results):
        return self._obtain_results(
            results, ["Certificate or Keystore disclosure"], ["warnings"]
        )
