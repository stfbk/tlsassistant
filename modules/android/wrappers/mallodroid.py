import logging
from os import sep
from pathlib import Path

from utils.logger import Logger
from utils.validation import Validator
from utils.loader import load_module


class Mallodroid:
    """
    Mallodroid is a tool to perform static analysis of Android applications.
    This wrapper is a python wrapper to mallodroid.py.
    """

    __cache = {}
    __instance = None

    def __init__(self):
        logging.getLogger("androguard.analysis").setLevel(
            logging.ERROR
            if not logging.getLogger().isEnabledFor(logging.DEBUG)
            else logging.DEBUG
        )  # remove annoying info messages
        self.__logging = Logger("Mallodroid")
        self.__mallodroid = f"dependencies{sep}mallodroid{sep}mallodroid.py"
        self.__instance = load_module(self.__mallodroid, "mallodroid")
        self.__input_dict = {}
        self.__correct_path = None

    def input(self, **kwargs):
        """
        This method is used to set the input

        :param kwargs:
        :Keyword Arguments:
            path: path to the file to be analyzed
            args: list of arguments to be passed to mallodroid
            force: force the analysis of the file (default: False)
        """
        self.__input_dict = kwargs

    def output(self, **kwargs) -> dict:
        """
        This method is used to get the output of the analysis

        :param kwargs:
        :Keyword Arguments:
            path: path to the file to be analyzed

        :return: a dictionary result
        :rtype: dict
        """
        return (
            self.__cache[kwargs["path"]]
            if "path" in kwargs and kwargs["path"] in self.__cache
            else {}
        )

    def run(self, **kwargs) -> dict:
        """
        This method is used to run the analysis

        :param kwargs:
        :Keyword Arguments:
            path: path to the file to be analyzed
            args: list of arguments to be passed to mallodroid
            force: force the analysis of the file ignoring cache (default: False)
        """
        self.input(**kwargs)
        if "path" in self.__input_dict:
            self.__correct_path = Path(self.__input_dict["path"])
            if not self.__correct_path.exists():
                raise FileNotFoundError(
                    f"Couldn't find the file {self.__correct_path}."
                )
        else:
            raise AssertionError("Path argument missing.")
        # validate input types
        args = self.__input_dict["args"] if "args" in self.__input_dict else []
        force = self.__input_dict["force"] if "force" in self.__input_dict else False
        Validator([(args, list), (force, bool)])

        self.__worker(self.__correct_path, args=args, force=force)
        return self.output(path=str(self.__correct_path.absolute()))

    def __worker(self, path: Path, args: list, force: bool):
        """
        This method is the worker method to be executed by run()

        :param path: path to the file to be analyzed
        :param args: list of arguments to be passed to mallodroid
        :param force: force the analysis of the file ignoring cache (default: False)

        """
        file_id = str(path.absolute())
        self.__logging.debug(f"Starting analysis of {file_id} ...")
        args.append("-f")
        args.append(str(path.absolute()))
        if force:
            self.__logging.debug(
                f"Analysis of {file_id} (cache miss or forced by call)"
            )
            self.__cache[file_id] = self.__instance.main(
                args,
                stdout_suppress=False
                if logging.getLogger().isEnabledFor(logging.DEBUG)
                else True,
                stderr_suppress=False
                if logging.getLogger().isEnabledFor(logging.DEBUG)
                else True,
            )  # calls main
        else:
            if file_id not in self.__cache:  # if not in cache, force analysis
                self.__worker(path, args, force=True)
