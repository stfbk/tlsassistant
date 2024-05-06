import logging
import signal
import threading
from pathlib import Path
import time
import os

from utils.logger import Logger
from utils.validation import Validator  
from utils.loader import load_module

import sys
sys.path.append("dependencies/SEBASTiAn/src")
from SEBASTiAn.main import perform_analysis_with_timeout

class Sebastian:
    """
    SEBESTiAn is a tool to perform static analysis of Android applications.
    This wrapper is a python wrapper to cly.py.
    """ 

    __cache = {}
    __instance = None

    def __init__(self) -> None:
        logging.getLogger("SEBASTiAn").setLevel(
            logging.ERROR
            if not logging.getLogger().isEnabledFor(logging.DEBUG)
            else logging.DEBUG
        )  # remove annoying info messages
        self.__logging = Logger("sebastian")
        self.__sebastian = f"dependencies{os.sep}SEBASTiAn{os.sep}src{os.sep}SEBASTiAn{os.sep}main.py"
        self.__instance = load_module(self.__sebastian, "sebastian")
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
          
        if force:
            self.__logging.debug(
                f"Analysis of {file_id} (cache miss or forced by call)"
            )
            try:
                self.__cache[file_id] = perform_analysis_with_timeout(file_id,timeout=60000)
            except Exception as e:
                self.__logging.error(f"Analysis of {file_id} crashed: {e}")
        else:
            if file_id not in self.__cache:  # if not in cache, force analysis
                self.__worker(path, args, force=True)