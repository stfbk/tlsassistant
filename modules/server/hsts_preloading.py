from modules.server.hsts_base import Hsts_base
from utils.logger import Logger


class Hsts_preloading(Hsts_base):
    """
    Analysis of the HSTS Preloading status
    """

    def _get_logger(self):
        """
        Logger for the module.

        :return: Logger
        :rtype: Logger
        """
        return Logger("Hsts Not Preloaded")

    # to override
    def _set_arguments(self):
        """
        Sets the module arguments.
        """
        self._arguments = self._instance.HSTSPRELOAD

    # to override
    def _worker(self, results):
        """
        Worker for the module.

        :param results: results to process
        :type results: dict
        :return: results obtained from processing
        :rtype: dict
        """
        return self._obtain_results(results)
