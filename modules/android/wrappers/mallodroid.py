import sys
from os import sep, path
import importlib.util
from pathlib import Path


def load_module(module_path: str, module_name: str) -> object:
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


class Mallodroid:
    __cache = {}
    __instance = None

    def __init__(self):
        self.__mallodroid = f"dependencies{sep}mallodroid{sep}mallodroid.py"
        self.__instance = load_module(self.__mallodroid, "mallodroid")
        self.__input_dict = {}
        self.__correct_path = None

    def input(self, **kwargs):
        self.__input_dict = kwargs

    def output(self, **kwargs) -> dict:
        return (
            self.__cache[kwargs["path"]]
            if "path" in kwargs and kwargs["path"] in self.__cache
            else {}
        )

    def run(self, **kwargs) -> dict:
        self.input(**kwargs)
        if "path" in self.__input_dict:
            self.__correct_path = Path(self.__input_dict["path"])
            if not self.__correct_path.exists():
                raise FileNotFoundError(
                    f"Couldn't find the file {self.__correct_path}."
                )
        else:
            raise AssertionError("Path argument missing.")

        self.worker(
            args=self.__input_dict["args"] if "args" in self.__input_dict else None
        )
        return self.output()

    def worker(self, args):
        old_args = sys.argv.copy()
        sys.argv = []
        sys.argv.append(f"-f {self.__correct_path}")
        sys.argv.append("-x")
        # todo: add mallodroid results
        sys.argv = sys.argv + (args if args else [])

        self.__instance.main()  # calls main

        # todo: file scan of mallodroid results

        sys.argv = old_args
