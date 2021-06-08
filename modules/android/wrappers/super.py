import json
import logging
import subprocess
import sys
import uuid
from os.path import devnull, sep, join
from pathlib import Path
from shutil import rmtree as rm_rf
from os import walk

from utils.logger import Logger
from utils.validation import Validator


class Parser:
    def __init__(self, results):
        self.__cache = {}
        self.__parse(results)

    def __remove_manifest(self, results):
        types = ["criticals", "highs", "mediums", "lows", "warnings"]

        for type in types:
            vulnerabilities = [
                vuln
                for vuln in results[type]
                if vuln["file"].lower() != "androidmanifest.xml"
            ]
            results[type] = vulnerabilities
            results[f"{type}_len"] = len(vulnerabilities)
        return results

    def __parse(self, results):
        self.__cache = self.__remove_manifest(results)

    def output(self):
        return self.__cache


class Super:
    __cache = {}

    def __init__(self):
        self.__logging = Logger("SUPER")
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

    def __find_file(self, folder):
        for dirpath, dirnames, filenames in walk(folder):
            for filename in [f for f in filenames if f == "results.json"]:
                return join(dirpath, filename)

    def run(self, **kwargs):
        # input parsing
        self.input(**kwargs)
        if "path" in self.__input_dict:
            self.__correct_path = Path(self.__input_dict["path"])
            if not self.__correct_path.exists():
                raise FileNotFoundError(
                    f"Couldn't find the file {self.__correct_path}."
                )
        else:
            raise AssertionError("Path argument missing.")

        args = self.__input_dict["args"] if "args" in self.__input_dict else []
        force = self.__input_dict["force"] if "force" in self.__input_dict else False
        Validator([(self.__input_dict["path"], str), (args, list), (force, bool)])
        self.__super_scan(self.__correct_path, args=args, force=force)
        return self.output(path=str(self.__correct_path.absolute()))

    def subprocess_call(self, cmd, null, try_again=False):
        try:
            subprocess.run(
                cmd,
                stderr=(
                    sys.stdout
                    if logging.getLogger().isEnabledFor(
                        logging.DEBUG
                    )  # if the user asked for debug mode, let him see the output.
                    else null  # else /dev/null
                ),
                stdout=(
                    sys.stdout
                    if logging.getLogger().isEnabledFor(
                        logging.DEBUG
                    )  # if the user asked for debug mode, let him see the output.
                    else null  # else /dev/null
                ),
                check=True,  # check call equivalent
                text=True,  # text as an input
                input="yes",  # if asked, write 'yes' on each prompt
            )
            return 1 if try_again else 0  # failed 1 times or zero times
        except subprocess.CalledProcessError as c:
            self.__logging.debug(str(c))
            if not try_again:
                self.subprocess_call(cmd, null, try_again=True)
            else:
                return 2  # failed two times

    def __super_scan(self, path: Path, args: list, force: bool):
        if force:
            self.__logging.debug("Starting SUPER analysis")
            folder_name = uuid.uuid4().hex
            self.__logging.debug(
                f"Scanning {path.absolute()}, saving result to temp folder {folder_name}"
            )
            with open(devnull, "w") as null:
                cmd = [
                    "super-analyzer",
                    "--results",
                    f"dependencies{sep}{folder_name}{sep}results",
                    "--dist",
                    f"dependencies{sep}{folder_name}{sep}dist",
                    "--rules",
                    f"configs{sep}tls_rules.json",
                    "--json",
                ]

                if args:
                    self.__logging.debug(f"Scanning with personalized args: {args}")
                    for arg in args:
                        cmd.append(arg)
                cmd.append(str(path.absolute()))
                exit_code = self.subprocess_call(cmd, null)
                self.__logging.debug(f"exit code: {exit_code}")
                file_name = self.__find_file(
                    f"dependencies{sep}{folder_name}{sep}results"
                )
                if Path(file_name).exists():  # load the temp file results
                    with open(file_name, "r") as file:  # load temp file
                        data = file.read()
                        self.__cache[str(path.absolute())] = Parser(
                            json.loads(data)
                        ).output()

                    rm_rf(f"dependencies{sep}{folder_name}")
                else:
                    raise Exception("Couldn't decompile the APK")
        else:
            if str(path.absolute()) not in self.__cache:
                self.__super_scan(path, args, force=True)
