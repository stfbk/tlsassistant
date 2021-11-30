from modules.server.hsts_base import Hsts_base
from modules.stix.stix_base import Bundled
from utils.logger import Logger
from utils.mitigations import load_mitigation


class Hsts_preloading(Hsts_base):
    """
    Analysis of the HSTS Preloading status
    """

    stix = Bundled(mitigation_object=load_mitigation("HSTS_PRELOADING"))

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
                "HSTS_NOT_PRELOADED", raise_error=False
            )  # todo: remove, debug until we have all mitigations
        return result if condition else {}

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
