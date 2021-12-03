from modules.android.super_base import Super_base
from modules.stix.stix_base import Bundled
from utils.logger import Logger
from utils.mitigations import load_mitigation


class Obfuscated_code(Super_base):
    """
    Check if the code is obfuscated
    """

    stix = Bundled(mitigation_object=load_mitigation("OBFUSCATED_CODE"))

    def _get_logger(self):
        """
        Get the logger of the module.
        :return: Logger
        """
        return Logger("Obfuscated code")

    # to override
    def _set_arguments(self):
        """
        Sets the arguments of the module.
        """
        self._arguments = []

    # to override
    def _worker(self, results):
        """
        The worker function of the module.

        :param results: dict
        :return: dict of results
        :rtype: dict
        """
        return self._obtain_results(results, ["Obfuscated code"], ["warnings"])
