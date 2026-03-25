from os.path import sep
from pathlib import Path

from modules.server.tlsfuzzer_base import Tlsfuzzer_base
from modules.stix.stix_base import Bundled
from utils.loader import load_configuration
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
        Set static arguments for the fuzzer.
        Cipher-dependent scripts are added at runtime from testssl output.
        """
        self._cipher_name_to_hex = self._load_cipher_name_to_hex()
        self._cert_location = f"dependencies{sep}certificates{sep}localuser.crt"
        self._key_location = f"dependencies{sep}certificates{sep}localuser.key"
        assert Path(self._cert_location).exists(), (
            f"The certificate isn't "
            f"present at location {Path(self._cert_location).absolute()}"
        )
        assert Path(self._key_location).exists(), (
            f"The certificate key isn't "
            f"present at location {Path(self._key_location).absolute()}"
        )

        self._arguments = [
            (
                "test-sig-algs", # this one does not allow cipher selection
                [],
                {
                    "only_one": True,
                    "cipher_xc013": "not support ciphers `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA` nor `TLS_DHE_RSA_WITH_AES_128_CBC_SHA`",
                    "cipher_x33": "not support ciphers `TLS_DHE_RSA_WITH_AES_128_CBC_SHA` nor `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA`"
                }
            ),
            (
                "test-clienthello-md5",
                [],
                {
                    "cipher_x6b": "not support cipher `TLS_DHE_RSA_WITH_AES_256_CBC_SHA256`"
                }
            ),
            (
                "test-tls13-pkcs-signature",
                [],
                {
                    "TLS1_3": "not support TLS 1.3"
                }
            ),
        ]

    def _post_filter_arguments(self, testssl_results: dict):
        """
        Add sloth scripts using ciphers discovered by testssl
        """
        supported_ciphers = self._extract_supported_ciphers(testssl_results)
        filtered_ciphers = self._filter_sloth_ciphers(supported_ciphers)

        # client impersonation
        for cipher in filtered_ciphers["client_impersonation"]:
            extra_flags = "-d" if "DHE" in cipher["name"] else ""
            self._arguments.append(
                (
                    "test-certificate-verify",
                    ["-k", self._key_location, "-c", self._cert_location, "-C", cipher["id"], extra_flags],
                )
            )

    def _load_cipher_name_to_hex(self) -> dict:
        """
        Build a map from IANA names (TLS_...) to hex values (0xHHHH)

        This is needed since tlsfuzzer fails on some older ciphersuites names
        """
        ciphersuites = load_configuration(
            "ciphersuites", "configs/compliance/")
        mapping = {}
        # TODO: mapping all of this is not really needed, we could do it on demand
        for hex_value, names in ciphersuites.items():
            iana_name = names.get("IANA", "")
            if not iana_name:
                continue
            compact_hex = hex_value.replace("0x", "").replace(",", "")
            hex_id = f"0x{compact_hex}"
            mapping[iana_name] = hex_id
        return mapping

    def _extract_supported_ciphers(self, testssl_results: dict) -> list:
        """
        Extract supported ciphers from endpoint result
        """
        ciphers = []
        for key, item in testssl_results.items():
            if not key.startswith("cipher_"):
                continue
            finding = item.get("finding", "")
            if not finding or finding == "ERROR_NOT_FOUND":
                continue
            if finding == "none" or "not offered" in finding:
                continue

            cipher_name = finding.split()[-1]
            cipher_hex = self._cipher_name_to_hex.get(cipher_name)
            if not cipher_hex:
                continue
            ciphers.append({"id": cipher_hex, "name": cipher_name})

        # de-dupliate by hex id
        return list({cipher["id"]: cipher for cipher in ciphers}.values())

    def _filter_sloth_ciphers(self, ciphers: list) -> dict:
        """
        Filter raw ciphersuites to test with sloth
        """
        sloth_targets = {
            "client_impersonation": [],
        }
        for cipher in ciphers:
            cipher_name = cipher["name"]
            if "WITH" not in cipher_name: # tls 1.2 always has WITH, tls 1.3 does not have it and it is not vulnerable
                continue
            if "PSK" in cipher_name or "ANON" in cipher_name:
                continue
            if "RSA" in cipher_name or "ECDSA" in cipher_name:
                sloth_targets["client_impersonation"].append(cipher)

        return sloth_targets

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
                "MITIGATION": "SLOTH"
            },
            "test-sig-algs": {
                "MD5 first": 2,
                "MITIGATION": "SLOTH"
            },
            "test-clienthello-md5": {
                "only-md5-rsa-signature_algorithm": 1,
                "unknown-signature_algorithm-numbers": 1,
                "MITIGATION": "SLOTH"
            },
            "test-tls13-pkcs-signature": {
                "rsa_pkcs1_md5 signature": 1,
                "MITIGATION": "SLOTH_MD5_SIGNATURE_TLS_1_3"
            },
        }
        for script in list(keys.keys()):
            if script not in results:
                keys.pop(script)
        return self._obtain_results(results, keys)
