from modules.android.mallodroid_base import Mallodroid_base
from modules.stix.stix_base import Bundled
from utils.logger import Logger
from utils.mitigations import load_mitigation


class Hostnameverifier(Mallodroid_base):
    """
    Checks if the device has a custom hostname.

    """

    stix = Bundled(mitigation_object=load_mitigation("HOSTNAME_VERIFIER"))

    def _get_logger(self):
        """
        Returns the module logger
        """
        return Logger("HostnameVerifier")

    def _set_mitigations(self, result: dict, key: str, condition: bool) -> dict:
        """
        Sets mitigations for the result.

        :param result: Result to be mitigated
        :param key: Key to be mitigated
        :param condition: If true, the mitigation is set
        :return: result with mitigation
        :rtype: dict
        """
        if condition:
            result["mitigation"] = load_mitigation(
                "HOSTNAME_VERIFIER", raise_error=False
            )  # todo: we are missing a mitigation!
        return result if condition else {}

    # to override
    def _set_arguments(self):
        """
        Sets the module arguments.
        """
        self._arguments = []

    # to override
    def _worker(self, results):
        """
        Worker function for the module.

        :param results: Result from the module
        :return: dict with results
        :rtype: dict
        """
        return self._obtain_results(
            results, ["customhostnameverifier", "allowallhostnameverifier"]
        )
