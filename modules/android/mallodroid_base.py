from modules.android.wrappers.mallodroid import Mallodroid
from utils.validation import Validator
from utils.mitigations import load_mitigation
import logging


class Mallodroid_base:
    def __init__(self):
        self._input_dict = {}
        self._arguments = []
        self._instance = Mallodroid()
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

    def _obtain_results(self, results: dict, keys: list):
        val = Validator([(results, dict), (keys, list)])
        out = {}

        for key in keys:
            val.string(key)
            for value in results[key]:
                if "empty" in value:
                    single = self._set_mitigations(value, key, value["empty"])
                    # removing useless information atm
                    single.pop("xref", None)
                    single.pop("java_b64", None)

                    if key not in out:
                        out[key] = []
                    if single:
                        out[key].append(single)
        return out

    def run(self, **kwargs):
        self.input(**kwargs)

        if "path" not in kwargs:
            raise AssertionError("path is missing!")
        Validator([(self._input_dict["path"], str)])
        self._input_dict["path"] = self._input_dict["path"]
        self._output_dict = self._worker(
            self._instance.run(path=self._input_dict["path"], args=self._arguments)
        )
        return self.output()

    def output(self):
        return self._output_dict
