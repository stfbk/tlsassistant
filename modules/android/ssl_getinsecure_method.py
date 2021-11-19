from modules.android.super_base import Super_base
from utils.logger import Logger


class Ssl_getinsecure_method(Super_base):
    """
    Check the presence of SSL getInsecure method in the application
    """

    def _get_logger(self):
        """
        The function returns the custom logger

        :return: Logger
        """
        return Logger("SSL getInsecure method")

    # to override
    def _set_arguments(self):
        """
        Setup all arguments
        """
        self._arguments = []

    # to override
    def _worker(self, results):
        """
        Run this module

        :param results: dict of results
        :return: dict of results of the module
        :rtype: dict
        """
        return self._obtain_results(results, ["SSL getInsecure method"], ["highs"])
