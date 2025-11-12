from modules.server.testssl_base import Testssl_base
from modules.stix.stix_base import Bundled
from utils.mitigations import load_mitigation
from utils.loader import load_configuration


class Pfs(Testssl_base):
    """
    Analysis of the pfs testssl results
    """

    stix = Bundled(mitigation_object=load_mitigation("PFS"))
    _ciphers_converter = load_configuration(
            "openssl_to_iana", "configs/compliance/")
    # to override
    def _set_arguments(self):
        self._arguments = ["-f", "-e"]

    def _set_mitigations(self, result: dict, key: str, condition: bool) -> dict:
        """
        Sets the mitigations for the given result

        :param result: the result to set the mitigations for
        :type result: dict
        :param key: the key of the result
        :type key: str
        :param condition: the condition to set the mitigations for
        :type condition: bool
        :return: the mitigations for the given result
        :rtype: dict
        """
        if key == "FS_ciphers" and " " in result["finding"]:
            secure_ciphers = result["finding"].split(" ")
            used_ciphers = self.ciphers_per_ip[self.currently_analysed_ip][self.currently_analysed_port].copy()
            to_remove = []
            for el in used_ciphers:
                element = [x for x in el.split(" ") if x]
                for c in secure_ciphers:
                    if c == element[1]:
                        to_remove.append(el)
            for el in to_remove:
                used_ciphers.remove(el)
            if used_ciphers:
                condition = True
        if condition:
            result["mitigation"] = load_mitigation("PFS")
        return result if condition else {}

    # to override
    def _worker(self, results):
        """
        The worker method, which runs the testssl command

        :param results: dict
        :return: dict
        :rtype: dict
        """
        self.ciphers_per_ip = self._get_ciphers_per_ip(results)
        return self._obtain_results(
            results,
            ["DH_groups", "pre_128cipher", "FS", "FS_ciphers", "FS_ECDHE_curves"],
        )
