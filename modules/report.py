from enum import Enum
from os import mkdir
from pathlib import Path
from utils.booleanize import boolean_results

from utils.validation import Validator, rec_search_key
from utils import output
from datetime import datetime
from os.path import sep
from utils.logger import Logger
from requests.structures import CaseInsensitiveDict
from jinja2 import Environment, FileSystemLoader
from pathlib import Path
from utils.globals import version
from distutils.dir_util import copy_tree as cp
from utils.prune import pruner


class Report:
    """
    Output Module that generates the report.

    """

    class Mode(Enum):
        """
        Enum for the report mode.
        """

        HOSTS = 0
        MODULES = 1

    def __init__(self):
        self.__input_dict = {}
        self.__path = ""
        self.__template_dir = Path(f"configs{sep}out_template")
        self.__logging = Logger("Report")

    def input(self, **kwargs):
        """
        Input function for the Report module.
        :param kwargs: Arguments for the Report module. See below.
        :type kwargs: dict

        :Keyword Arguments:
        * *results* (dict) -- Dictionary containing the results of the scan.
        * *path* (string) -- Path to the report.
        * *mode* (Mode) -- Report mode.
        * *modules* (list) -- List of modules to include in the report.
        """
        self.__input_dict = kwargs

    def __modules_report_formatter(self, results: dict, modules: list):
        self.__logging.info(f"Generating modules report..")
        out = {}
        for module in modules:
            vuln_hosts = []
            if module not in out:
                out[module] = {}
            for hostname in results:
                self.__logging.debug(f"Generating report for {hostname}")
                if module in results[hostname]:
                    if "Entry" in results[hostname][module]:
                        out[module] = CaseInsensitiveDict(
                            results[hostname][module]["Entry"]
                        )
                    if hostname not in vuln_hosts:
                        vuln_hosts.append(hostname)
            if vuln_hosts:
                out[module]["hosts"] = vuln_hosts.copy()
        return out

    def __hosts_report_formatter(self, results: dict):
        self.__logging.info(f"Generating hosts report..")
        for hostname in results:
            # the results are good, we need to remove the "Entry" key but preserve the rest with the CaseInsensitiveDict
            for module in results[hostname]:
                if "Entry" in results[hostname][module]:
                    results[hostname][module] = CaseInsensitiveDict(
                        results[hostname][module]["Entry"]
                    )
        return results

    def __jinja2__report(
        self, mode: Mode, results: dict, modules: list, date: datetime.date
    ):
        self.__logging.debug(f"Generating report in jinja2..")
        fsl = FileSystemLoader(searchpath=self.__template_dir)
        env = Environment(loader=fsl)
        to_process = {"version": version, "date": date, "modules": modules}
        if mode == self.Mode.MODULES:
            template = env.get_template(f"modules_report.html")
            to_process["results"] = self.__modules_report_formatter(results, modules)
        elif mode == self.Mode.HOSTS:
            template = env.get_template(f"hosts_report.html")
            to_process["results"] = self.__hosts_report_formatter(results)
        else:
            raise ValueError(f"Unknown mode: {mode}")
        return template.render(**to_process)

    def __extract_results(self, res: dict) -> tuple:
        # due to the fact that the results are in a dict with the loaded_modules, we have to extract the results
        # by removing the loaded_modules
        modules = {}
        for hostname in res:
            if "loaded_modules" in res[hostname]:
                modules.update(res[hostname]["loaded_modules"].copy())
                del res[hostname]["loaded_modules"]
                res[hostname] = res[hostname]["results"]
        return res, modules

    def run(self, **kwargs):
        """
        Runs the report.

        :param kwargs: Arguments for the Report module. See below.
        :type kwargs: dict

        :Keyword Arguments:
        * *results* (dict) -- Dictionary containing the results of the scan.
        * *path* (string) -- Path to the report.
        * *mode* (Mode) -- Report mode.
        * *modules* (list) -- List of modules to include in the report.
        """

        self.input(**kwargs)
        assert "path" in self.__input_dict, "Missing output path"
        assert "results" in self.__input_dict, "Missing results list"
        assert "mode" in self.__input_dict, "Missing mode"

        path = self.__input_dict["path"]
        self.__path = Path(path)

        Validator(
            [
                (path, str),
                (self.__input_dict["results"], dict),
                (self.__input_dict["mode"], self.Mode),
            ]
        )

        if not Path("results").exists():
            self.__logging.debug("Adding result folder...")
            mkdir("results")
            self.__logging.debug("Copying assets folder...")
            cp(
                str(Path(f"configs{sep}out_template{sep}assets").absolute()),
                str(Path(f"results{sep}assets").absolute()),
            )

        output_file = Path(f"results{sep}{self.__path.stem}.html")
        output_path = output_file.absolute()
        results, modules = self.__extract_results(
            self.__input_dict["results"]
        )  # obtain results removing loaded_modules
        results = pruner(results)  # prune empty results
        # now, we want to divide raw from mitigations
        for hostname in results:
            for module in results[hostname]:
                raw = results[hostname][module].copy()
                for mitigation in rec_search_key(
                    "mitigation", raw
                ):  # remove mitigation in raw results
                    mitigation = "check below"
                for mitigation in rec_search_key(
                    "mitigation", results[hostname][module]
                ):
                    if mitigation is not None:
                        results[hostname][
                            module
                        ] = (
                            mitigation.copy()
                        )  # i'm expecting only one mitigation per module, is it ok?
                results[hostname][module]["raw"] = raw
        with open(output_path, "w") as f:
            f.write(
                self.__jinja2__report(
                    mode=self.__input_dict["mode"],
                    modules=list(modules.keys()),
                    results=results,
                    date=datetime.now(),
                )
            )
        self.__logging.debug("Checking if needs pdf...")

        if self.__path.suffix.lower() == ".pdf":
            output_path = f"{output_file.absolute().parent}{sep}{output_file.stem}.pdf"
            self.__logging.debug("Starting HTML to PDF...")
            output.html_to_pdf(str(output_file.absolute()), output_path)
        self.__logging.info(f"Report generated at {output_path}")
        # todo: add PDF library
