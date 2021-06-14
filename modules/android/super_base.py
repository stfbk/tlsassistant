from modules.android.wrappers.super import Super
from utils.validation import Validator
from utils.mitigations import load_mitigation


class Super_base:
    def __init__(self):
        self._input_dict = {}
        self._arguments = []
        self._instance = Super()
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

    def _obtain_results(self, results: dict, keys: list, types: list):
        val = Validator([(results, dict), (keys, list), (types, list)])
        out = {}

        for key in keys:
            val.string(key)
            for type_ in types:
                val.string(type_)
                for value in results[type_]:
                    if value['name'].lower() == key.lower():
                        single = self._set_mitigations(value, value["name"], True)
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
