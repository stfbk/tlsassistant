import logging
import subprocess

from utils.urls import url_domain, cache_name
from utils.validation import Validator
from pathlib import Path
from os.path import sep
from os import remove
from shutil import copyfile


class Tlsfuzzer:
    """
    Tlsfuzzer is a tool for testing TLS connections.

    this is a wrapper around tlslite and tlsfuzzer.
    """

    __cache = {}

    def __init__(self):
        self.__input_dict = {}
        self.__output = {}

    def input(self, **kwargs):
        """
        Input arguments for tlsfuzzer.

        :param kwargs:
        :type kwargs: dict

        :Keyword Arguments:
            * *hostname* (``str``) -- Hostname to analyze.
            * *scripts* (``list``) -- Scripts to run.
            * *port* (``str``) -- Port to connect to.
            * *force* (``bool``) -- Force to run the script by ignoring cache.
        """
        self.__input_dict = kwargs

    def output(self, **kwargs) -> dict:
        """
        Output of tlsfuzzer.

        :param kwargs:
        :type kwargs: dict

        :Keyword Arguments:
            * *hostname* (``str``) -- Hostname to analyze.
            * *port* (``str``) -- Port to connect to.
            * *scripts* (``list``) -- Scripts to run.

        """
        hostname_cache = cache_name(
            kwargs["hostname"], kwargs["port"] if "port" in kwargs else "443"
        )
        if "hostname" not in kwargs or hostname_cache not in self.__cache:
            return {}
        elif "scripts" not in kwargs:
            return self.__cache[hostname_cache]
        else:
            Validator().list(kwargs["scripts"])
            output = {}
            for script in kwargs["scripts"]:
                if script in self.__cache[hostname_cache]:
                    output[script] = self.__cache[hostname_cache][script]
            logging.debug(output)
            return output

    def run(self, **kwargs):

        """
        Run tlsfuzzer.

        :param kwargs:
        :type kwargs: dict

        :Keyword Arguments:
            * *hostname* (``str``) -- Hostname to analyze.
            * *scripts* (``list``) -- Scripts to run.
            * *port* (``str``) -- Port to connect to.
            * *force* (``bool``) -- Force to run the script by ignoring cache.

        :return: dict -- Output of tlsfuzzer.
        :rtype: dict

        """
        self.input(**kwargs)
        if "hostname" not in self.__input_dict:
            raise AssertionError("IP or hostname args not found.")
        elif "scripts" not in self.__input_dict:
            raise AssertionError("Script list args not found.")
        self.__input_dict["hostname"] = url_domain(self.__input_dict["hostname"])
        scripts = self.__input_dict["scripts"]

        force = self.__input_dict["force"] if "force" in self.__input_dict else False
        Validator(
            [
                (self.__input_dict["hostname"], str),
                (self.__input_dict["port"] if "port" in self.__input_dict else "", str),
                (force, bool),
                (scripts, list),
            ]
        )
        path_scripts = []
        validate = Validator()
        # parse list of tuples
        script_names = []
        for script in scripts:
            # accepting script,args
            validate.obj(script, tuple)  # validate for tuple
            if len(script) != 2:
                raise AssertionError("This script accepts only 2-value tuples")
            script_name, script_args = script
            validate.string(script_name)
            validate.list(script_args)

            script_name = (
                script_name[-3] if script_name.endswith(".py") else script_name
            )
            script_names.append(script_name)
            tmp_path = Path(
                f"dependencies{sep}tlsfuzzer{sep}scripts{sep}{script_name}.py"
            )
            if not tmp_path.exists():
                raise FileNotFoundError(f"file {script_name} not found.")
            dest = copyfile(
                str(tmp_path.absolute()), f"{tmp_path.parents[1]}{sep}{tmp_path.name}"
            )  # copy file for tlsfuzzer workaround
            tmp_path = Path(dest)
            path_scripts.append((tmp_path, script_args))

        self.__worker(
            self.__input_dict["hostname"],
            path_scripts,
            force,
            port=self.__input_dict["port"],
        )
        return self.output(hostname=self.__input_dict["hostname"], scripts=script_names, port=self.__input_dict["port"])

    def __worker(self, hostname: str, scripts: list, force: bool, port="443"):
        """
        Internal worker for run.

        :param hostname: Hostname to analyze.
        :type hostname: str
        :param scripts: Scripts to run.
        :type scripts: list
        :param force: Force to run the script by ignoring cache.
        :type force: bool
        :param port: Port to connect to.
        :type port: str
        """
        hostname_cache = cache_name(hostname, port)
        if force:
            for script in scripts:

                script_name, script_args = script
                cmd = [
                    "python3",
                    f"{script_name}",
                    "-h",
                    f"{hostname}",
                    "-p",
                    f"{port}",
                ]
                cmd += script_args
                logging.debug(
                    f"Calling {script_name} for {hostname}{' with args ' + ' '.join(script_args) if script_args else ''} ..."
                )
                try:
                    output = subprocess.check_output(cmd).decode()
                except subprocess.CalledProcessError as c:
                    logging.debug(c)
                    output = c.output.decode()
                if (
                    script_name.exists()
                ):  # workaround, remove temp file moved to the root of tlsfuzzer
                    remove(str(script_name.absolute()))
                if hostname_cache not in self.__cache:
                    self.__cache[hostname_cache] = {}
                self.__cache[hostname_cache][script_name.stem] = output
        else:
            script_args = {}
            for script in scripts:  # prepare index dict
                script_name, script_arguments = script
                script_args[script_name.stem] = script
            if hostname_cache not in self.__cache:
                self.__worker(hostname, scripts, force=True, port=port)
            elif set(list(script_args.keys())) != set(
                list(self.__cache[hostname_cache].keys())
            ):
                difference_keys = list(
                    set(list(script_args.keys()))
                    - set(list(self.__cache[hostname_cache].keys()))
                )  # remove what is already cached
                difference = [script_args[key] for key in difference_keys]
                logging.debug(
                    "[TLSFuzzer Caching System] I've found results. Here the scripts which are not in cache"
                )
                logging.debug(difference)
                self.__worker(hostname, difference, force=True, port=port)
                for key, value in script_args.items():
                    if value[
                        0
                    ].exists():  # workaround, remove temp file moved to the root of tlsfuzzer
                        remove(str(value[0].absolute()))
