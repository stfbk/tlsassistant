from modules.android.super_base import Super_base
from utils.logger import Logger


class Weak_algorithms(Super_base):
    """
    Analyze the application to find the known weak algorithms.
    """

    def _get_logger(self):
        """
        Get the a logger instance.

        :return: the logger instance
        :rtype: Logger
        """
        return Logger("Weak Algorithms")

    # to override
    def _set_arguments(self):
        """
        Setup all the arguments.
        """
        self._arguments = []

    # to override
    def _worker(self, results):
        """
        Run the application.

        :param results: the results to update
        :rtype: dict
        :return: the results
        :rtype: dict
        """
        return self._obtain_results(results, ["Weak Algorithms"], ["highs"])
