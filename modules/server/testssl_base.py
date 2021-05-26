from modules.server.wrappers.testssl import Testssl
from utils.validation import Validator
from utils.urls import url_domain
from utils.mitigations import load_mitigation
import logging


class Testssl_base:
    def __init__(self):
        self._input_dict = {}
        self._arguments = []
        self._instance = Testssl()
        self._output_dict = {}
        self._mitigations = {}
        self._set_arguments()

    def input(self, **kwargs):
        self._input_dict = kwargs

    def _set_mitigations(self, result: dict, key: str) -> dict:
        result["mitigation"] = load_mitigation(key)
        return result

    # to override
    def _set_arguments(self):
        raise NotImplementedError("This method should be reimplemented!")

    # to override
    def _worker(self, results):
        raise NotImplementedError("This method should be reimplemented!")

    def _obtain_results(self, results: dict, keys: list):
        val = Validator([(results, dict), (keys, list)])
        out = {}
        for ip in results:
            for key in keys:
                val.string(key)
                if key not in results[ip]:
                    results[ip][key] = {"finding": "ERROR_NOT_FOUND"}
                if ip not in out:
                    out[ip] = {}
                # check for severity != OK or info
                if "severity" in results[ip][key] and (
                    results[ip][key]["severity"] != "OK"
                    or results[ip][key]["severity"] != "INFO"
                ):
                    out[ip][key] = self._set_mitigations(results[ip][key], key)
        return out

    def run(self, **kwargs):
        self.input(**kwargs)

        if "hostname" not in kwargs:
            raise AssertionError("Hostname is missing!")
        Validator([(self._input_dict["hostname"], str)])
        self._input_dict["hostname"] = url_domain(self._input_dict["hostname"])

        logging.debug(
            f"Executing analysis in {self._input_dict['hostname']} with args {self._arguments}"
        )

        self._output_dict = self._worker(
            self._instance.run(
                hostname=self._input_dict["hostname"],
                args=self._arguments,
                force=True,  # todo: remove for debug atm
            )
        )
        return self.output()

    def output(self):
        return self._output_dict
