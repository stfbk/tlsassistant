from modules.configuration.configuration_base import Parse_configuration_strict_security
from modules.server.hsts_base import Hsts_base
from modules.stix.stix_base import Bundled
from utils.logger import Logger
from utils.mitigations import load_mitigation


class Hsts_set(Hsts_base):
    """
    Analize results and check if HSTS is set
    """

    conf = (
        Parse_configuration_strict_security()
    )  # TODO: Check for port 443 or apply it everywhere?
    stix = Bundled(mitigation_object=load_mitigation("HSTS_SET"))

    def _get_logger(self):
        """
        Logger for HSTS_set module

        :return: Logger
        :rtype: Logger
        """
        return Logger("Hsts Not Set")

    def _set_mitigations(self, result: dict, key: str, condition: bool) -> dict:
        """
        Sets the mitigations for the analysis.

        :param result: the result dict
        :type result: dict
        :param key: the key to be used for the mitigations
        :type key: str
        :param condition: the condition to be used for the mitigations
        :type condition: bool
        :return: the result dict with the mitigations
        :rtype: dict
        """
        if condition:
            result["mitigation"] = load_mitigation(
                "HSTS_NOT_SET", raise_error=False
            )  # todo: remove, debug until we have all mitigations
        return result if condition else {}

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
