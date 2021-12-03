from modules.android.mallodroid_base import Mallodroid_base
from modules.stix.stix_base import Bundled
from utils.logger import Logger
from utils.mitigations import load_mitigation


class Trustmanager(Mallodroid_base):
    """
    Check if the app uses a custom TrustManager.
    """

    stix = Bundled(mitigation_object=load_mitigation("TRUST_MANAGER"))

    def _get_logger(self):
        """
        Logger for this module.

        :return: Logger
        :rtype: Logger
        """
        return Logger("TrustManager")

    def _set_mitigations(self, result: dict, key: str, condition: bool) -> dict:
        if condition:
            result["mitigation"] = load_mitigation("TRUST_MANAGER")
        return result if condition else {}

    # to override
    def _set_arguments(self):
        """
        Set arguments for the module.
        """
        self._arguments = []

    # to override
    def _worker(self, results):
        """
        Run the module.

        :param results: Results from analysis.
        :type results: dict
        :return: Results from analysis of the module.
        :rtype: dict
        """
        return self._obtain_results(results, ["trustmanager", "insecuresocketfactory"])
