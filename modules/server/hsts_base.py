from utils.validation import Validator
from utils.urls import url_domain, port_parse
from utils.mitigations import load_mitigation
from modules.server.wrappers.https_hsts import Https


class Hsts_base:
    def __init__(self):
        self._input_dict = {}
        self._arguments = []
        self._instance = Https()
        self._output_dict = {}
        self._mitigations = {}
        self._set_arguments()
        self.__logging = self._get_logger()

    def _get_logger(self):
        raise NotImplementedError("This method should be reimplemented!")

    def input(self, **kwargs):
        self._input_dict = kwargs

    def _set_mitigations(self, result: dict, key: str, condition: bool) -> dict:
        if condition:
            result["mitigation"] = load_mitigation(
                key, raise_error=False
            )  # todo: remove, debug until we have all mitigations
        return result if condition else {}

    # to override
    def _set_arguments(self):
        raise NotImplementedError("This method should be reimplemented!")

    # to override
    def _worker(self, results):
        raise NotImplementedError("This method should be reimplemented!")

    def _get_var_name(self):
        if self._arguments == self._instance.HTTPS:
            key = "HTTPS_NOT_ENFORCED"
        elif self._arguments == self._instance.HSTSSET:
            key = "HSTS_NOT_SET"
        elif self._arguments == self._instance.HSTSPRELOAD:
            key = "HSTS_NOT_PRELOADED"
        else:
            key = "SERVERINFO"
        return key

    def _obtain_results(self, results: bool or str):
        Validator(
            [
                (results, (bool, str)),  # bool if not serverinfo, else str
            ]
        )
        results = not results  # because of the logic of the mitigations
        conditioned_result = {self._input_dict["hostname"]: results}

        key = self._get_var_name()
        if self._arguments != self._instance.SERVERINFO and isinstance(results, bool):
            conditioned_result = self._set_mitigations(conditioned_result, key, results)
        out = {key: conditioned_result}
        return out

    def run(self, **kwargs):
        self.input(**kwargs)

        if "hostname" not in kwargs:
            raise AssertionError("Hostname is missing!")
        Validator([(self._input_dict["hostname"], str)])
        self._input_dict["hostname"] = url_domain(self._input_dict["hostname"])

        self.__logging.debug(
            f"Executing analysis in {self._input_dict['hostname']} with args {self._arguments}"
        )

        self._output_dict = self._worker(
            self._instance.run(
                hostname=self._input_dict["hostname"],
                port=self._input_dict['port'],
                type=self._arguments,
                force=True,
            )
        )
        return self.output()

    def output(self):
        return self._output_dict
