from modules.android.super_base import Super_base
from utils.logger import Logger


class Certificate_keystore_disclosure(Super_base):
    """
    Check if the application has a certificate or keystore

    """

    def _get_logger(self):
        """
        Get the logger of the module.
        """
        return Logger("Certificate or Keystore disclosure")

    # to override
    def _set_arguments(self):
        """
        Setup all the arguments.
        """
        self._arguments = []

    # to override
    def _worker(self, results):
        """
        Run module.
        :param results: results to process
        :type results: dict
        :return: Results obtained from module
        :rtype: dict
        """
        return self._obtain_results(
            results, ["Certificate or Keystore disclosure"], ["warnings"]
        )
