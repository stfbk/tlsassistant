from os.path import sep
from pathlib import Path

from modules.server.tlsfuzzer_base import Tlsfuzzer_base
from utils.logger import Logger


class Sloth(Tlsfuzzer_base):
    def _get_logger(self):
        return Logger("SLOTH")

    # to override
    def _set_arguments(self):
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
