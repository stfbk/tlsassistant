from modules.server.testssl_base import Testssl_base
import logging

from modules.stix.stix_base import Bundled
from utils.mitigations import load_mitigation


class Certificate_transparency(Testssl_base):

    """
    Analysis of the certificate transparency testssl results
    """

    stix = Bundled(mitigation_object=load_mitigation("CERTIFICATE_TRANSPARENCY"))
    # to override
    def _set_arguments(self):
        """
        Sets the arguments for the testssl command
        """
        self._arguments = ["-S"]

    # to override
    def _worker(self, results):
        """
        The worker method, which runs the testssl command

        :param results: dict
        :return: dict
        :rtype: dict
        """
        return self._obtain_results(results, ["certificate_transparency"])
