from os.path import sep
from pathlib import Path

from modules.server.tlsfuzzer_base import Tlsfuzzer_base
from modules.stix.stix_base import Bundled
from utils.logger import Logger
from utils.mitigations import load_mitigation


class Sloth(Tlsfuzzer_base):
    """
    Analysis of the sloth tlsfuzzer output
    """

    stix = Bundled(mitigation_object=load_mitigation("SLOTH"))

    def _get_logger(self):
        """
        Set up the logger

        :return: Logger
        :rtype: Logger
        """
        return Logger("SLOTH")

    # to override
    def _set_arguments(self):
        """
        Set the arguments for the fuzzer
        """
        cert_location = f"dependencies{sep}certificates{sep}localuser.crt"
        key_location = f"dependencies{sep}certificates{sep}localuser.key"
        assert Path(cert_location).exists(), (
            f"The certificate isn't "
            f"present at location {Path(cert_location).absolute()}"
        )
        assert Path(key_location).exists(), (
            f"The certificate key isn't "
            f"present at location {Path(key_location).absolute()}"
        )
        self._arguments = [
            (
                "test-certificate-verify",
                ["-k", key_location, "-c", cert_location],
            ),
            (
                "test-sig-algs",
                [],
            ),
            (
                "test-clienthello-md5",
                [],
            ),
            (
                "test-tls13-pkcs-signature",
                [],
            ),
        ]

    # to override
    def _worker(self, results):
        """
        perform the analysis of the fuzzer output for sloth

        :param results: the results of the fuzzer
        :type results: dict
        :return: Dict of sloth results
        :rtype: dict
        """
        keys = {
            "test-certificate-verify": {
                "MD5 forced": 2,
                "TLSv1.1 signature in TLSv1.2 Certificate Verify": 1,
                "MITIGATION": "SLOTH",
            },
            "test-sig-algs": {"MD5 first": 2, "MITIGATION": "SLOTH"},
            "test-clienthello-md5": {
                "only-md5-rsa-signature_algorithm": 1,
                "unknown-signature_algorithm-numbers": 1,
                "MITIGATION": "SLOTH",
            },
            "test-tls13-pkcs-signature": {
                "rsa_pkcs1_md5 signature": 1,
                "MITIGATION": "SLOTH_MD5_SIGNATURE_TLS_1_3",
            },
        }
        return self._obtain_results(results, keys)
