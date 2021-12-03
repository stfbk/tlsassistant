from modules.android.super_base import Super_base
from modules.stix.stix_base import Bundled
from utils.logger import Logger
from utils.mitigations import load_mitigation


class Weak_algorithms(Super_base):
    """
    Analyze the application to find the known weak algorithms.
    """

    stix = Bundled(mitigation_object=load_mitigation("WEAK_ALGORITHMS"))

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
