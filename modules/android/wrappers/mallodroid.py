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

        self.__worker(self.__correct_path,
                      args=self.__input_dict["args"] if "args" in self.__input_dict else None,
                      force=self.__input_dict["force"] if "force" in self.__input_dict else False
                      )
        return self.output(path=self.__correct_path.absolute())

    def __worker(self, path: Path, args: list, force: bool):
        file_id = path.absolute()
        if force:  # todo: come salvo il file? univocamente
            self.__cache[file_id] = self.__instance.main(path.absolute(), args, suppress_stdout=True,
                                                         suppress_stderr=True)  # calls main
        else:
            if file_id not in self.__cache:
                self.__worker(path, args, force)
