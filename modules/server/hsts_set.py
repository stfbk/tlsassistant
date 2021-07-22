from modules.configuration.configuration_base import Parse_configuration_strict_security
from modules.server.hsts_base import Hsts_base
from utils.logger import Logger


class Hsts_set(Hsts_base):
    """
    Analize results and check if HSTS is set
    """

    conf = (
        Parse_configuration_strict_security()
    )  # TODO: Check for port 443 or apply it everywhere?

    def _get_logger(self):
        """
        Logger for HSTS_set module

        :return: Logger
        :rtype: Logger
        """
        return Logger("Hsts Not Set")

    # to override
    def _set_arguments(self):
        """
        Set module arguments
        """
        self._arguments = self._instance.HSTSSET

    # to override
    def _worker(self, results):
        """
        Analyze results of check_hsts_set

        :param results: Results from hsts check
        :type results: dict
        :return: refined results of hsts
        :rtype: dict
        """
        return self._obtain_results(results)
