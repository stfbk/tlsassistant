import json
import os.path
import re
from datetime import datetime
from shutil import copytree as cp
from enum import Enum
from os import mkdir
from os.path import sep
from pathlib import Path
from pprint import pformat

import requests
from jinja2 import Environment, FileSystemLoader
from requests.structures import CaseInsensitiveDict
from z3c.rml import rml2pdf

import utils.loader
from modules.server.webserver_type import WebserverType
from modules.stix.stix import Stix
from utils.globals import version
from utils.logger import Logger
from utils.prune import pruner
from utils.validation import Validator, rec_search_key


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
        APK = 2 
        IPA = 3

    def __init__(self):
        self.__input_dict = {}
        self.__path = ""
        self.__template_dir = Path(f"configs{sep}out_template")
        self.__logging = Logger("Report")
        files = utils.loader.load_configuration("module_to_mitigation", "configs/")
        custom_fonts = utils.loader.load_configuration("custom_fonts", "configs/out_template/assets/pdf/")
        self._replacements = {"name_mapping": {},
                              'sub': re.sub,
                              # These replacements are applied only to the content of Textual, Apache and Nginx strings
                              "Replacements": {
                                  # Since the hyperlinks are not blue in RML we do it manually
                                  "(<a href=.*?</a>)": "<font color=\"blue\">\\1</font>",
                                  # Since the code tag is not directly supported in RML, we crete it with the font tag
                                  "<code>(.*?)</code>": "<font color=\"#d63384\" fontName=\"Roboto\">\\1</font>",
                                  "&nbsp;": "&#160;",
                                  # The paragraph tags are removed because they are not needed in the RML format
                                  "<p>": "",
                                  "</p>": "",
                                  "(<b>.*?</b>)": "<font fontName=\"Roboto Bold\">\\1</font>",
                                  "(<i>.*?</i>)": "<font fontName=\"Roboto Italic\">\\1</font>",
                                }
                              }
        for custom_font in custom_fonts:
            # Custom fonts must be defined in both html and custom_fonts.json
            self._replacements["Replacements"][f"<{custom_font}>(.*?)</{custom_font}>"] =\
                f"<font {custom_fonts[custom_font]}>\\1</font>"
        for module in files:
            # TODO fix poodle alias system
            if os.path.isfile(Path("configs/mitigations/" + files[module])):
                with open(Path("configs/mitigations/" + files[module]), "r") as f:
                    data = json.load(f)
                self._replacements["name_mapping"][module] = data.get("Entry", {}).get("Name", "Unknown")

    def input(self, **kwargs):
        """
        Input function for the Report module.
        :param kwargs: Arguments for the Report module. See below.
        :type kwargs: dict

        :Keyword Arguments:
        * *results* (dict) -- Dictionary containing the results of the scan.
        * *path* (string) -- Path to the report.
        * *mode* (Mode) -- Report mode.
        * *stix* (bool) -- If True, the report will be in STIX format.
        * *webhook* (string) -- Webhook to send the report to.
        * *prometheus* (string) -- Prometheus file path.
        """
        self.__input_dict = kwargs

    def __modules_report_formatter(self, results: dict, modules: list) -> dict:
        """
        Formats the results of the modules.

        :param results: Dictionary containing the results of the scan.
        :type results: dict
        :param modules: List of modules to include in the report.
        :type modules: list
        :return: Dictionary containing the results of the scan.
        :rtype: dict
        """
        out = {}
        for module in modules:
            vuln_hosts = []
            raw_results = {}
            if module not in out:
                out[module] = {}
            for hostname in results:
                if "errors" in results[hostname]:
                    out["errors"] = results[hostname]["errors"]
                self.__logging.debug(f"Generating report for {hostname}")
                if module in results[hostname]:
                    if "raw" in results[hostname][module]:
                        raw_results[hostname] = results[hostname][module]["raw"].copy()
                    if "Entry" in results[hostname][module]:
                        out[module] = CaseInsensitiveDict(
                            results[hostname][module]["Entry"]
                        )
                    if hostname not in vuln_hosts:
                        vuln_hosts.append(hostname)
            if raw_results:
                out[module]["raw"] = pformat(raw_results.copy(), indent=2)
            if vuln_hosts:
                out[module]["hosts"] = vuln_hosts.copy()
            if not out[module]:
                del out[module]
        return out

    def __hosts_report_formatter(self, results: dict) -> dict:
        """
        Formats the results of the hosts.

        :param results: Dictionary containing the results of the scan.
        :type results: dict
        :return: Dictionary containing the results of the scan.
        :rtype: dict
        """
        out = {}
        for hostname in results:
            # the results are good, we need to remove the "Entry" key but preserve the rest with the CaseInsensitiveDict
            if hostname not in out:
                out[hostname] = {}
            if "errors" in results[hostname]:
                out[hostname]["errors"] = results[hostname]["errors"][hostname]
            for module in results[hostname]:
                raw_results = {}
                if "raw" in results[hostname][module]:
                    raw_results = results[hostname][module]["raw"].copy()
                if "Entry" in results[hostname][module]:
                    out[hostname][module] = CaseInsensitiveDict(
                        results[hostname][module]["Entry"]
                    )
                    if raw_results:
                        out[hostname][module]["raw"] = pformat(
                            raw_results.copy(), indent=2
                        )
        return out

    def __jinja2__report(
            self, mode: Mode, results: dict, modules: list, date: datetime.date, rml: bool = False
    ):
        """
        Generates the report using jinja2.

        :param mode: Report mode.
        :type mode: Mode
        :param results: Dictionary containing the results of the scan.
        :type results: dict
        :param modules: List of modules to include in the report.
        :type modules: list
        :param date: Date of the scan.
        :type date: datetime.date
        :param rml: Whether to apply jinja2 to rml files or not.
        :type rml: bool
        """
        self.__logging.debug("Generating report in jinja2..")
        fsl = FileSystemLoader(searchpath=self.__template_dir)
        env = Environment(loader=fsl)
        file_extension = "xml" if rml else "html"
        to_process = {"version": version, "date": date, "modules": modules, "hosts": list(results.keys())}
        
        if mode == self.Mode.MODULES:
            self.__logging.info("Generating modules report..")
            template = env.get_template(f"modules_report.{file_extension}")
            to_process["results"] = self.__modules_report_formatter(results, modules)
        elif mode == self.Mode.HOSTS:
            self.__logging.info("Generating hosts report..")
            template = env.get_template(f"hosts_report.{file_extension}")
            to_process["type"] = "HOSTS"
            to_process["results"] = self.__hosts_report_formatter(results)
        # TODO group by module for APK and IPA
        elif mode == self.Mode.APK:
            self.__logging.info("Generating APK report..")
            template = env.get_template(f"hosts_report.{file_extension}")
            to_process["type"] = "APK"
            to_process["results"] = self.__hosts_report_formatter(results)
        elif mode == self.Mode.IPA:
            self.__logging.info("Generating IPA report..")
            template = env.get_template(f"hosts_report.{file_extension}")
            to_process["type"] = "IPA"
            to_process["results"] = self.__hosts_report_formatter(results)
        else:
            raise ValueError(f"Unknown mode: {mode}")
        to_process = {**to_process, **self._replacements, **{"pruner": pruner}}
        return template.render(**to_process)

    def __extract_results(self, res: dict) -> tuple:
        """
        Extracts the results from the input dictionary.

        :param res: Input dictionary.
        :type res: dict
        :return: Tuple containing the results and the modules.
        :rtype: tuple
        """
        # due to the fact that the results are in a dict with the loaded_modules, we have to extract the results
        # by removing the loaded_modules
        modules = {}
        for hostname in res:
            if "loaded_modules" in res[hostname]:
                modules.update(res[hostname]["loaded_modules"].copy())
                del res[hostname]["loaded_modules"]
                res[hostname] = res[hostname]["results"]
        return res, modules

    # sending results to the webhook with an exception safe way
    def __send_webhook(
            self,
            webhook_url: str,
            results: dict,
            modules: dict,
            post=True,
            result_param="results",
            modules_param="modules",
            other_params=None,
    ):
        """
        Sends the results to the webhook.

        :param webhook_url: Webhook URL.
        :type webhook_url: str
        :param results: Dictionary containing the results of the scan.
        :type results: dict
        :param modules: Dictionary containing the loaded modules.
        :type modules: dict
        """
        if other_params is None:
            other_params = {}
        self.__logging.debug("Sending results to webhook..")
        try:
            json_data = {
                result_param: pformat(results, indent=2),
                modules_param: pformat(modules, indent=2),
                "version": version,
                "date": str(datetime.today()),
            }
            json_data.update(other_params)
            headers = {
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) "
                              "AppleWebKit/537.36 (KHTML, like Gecko) "
                              "Chrome/39.0.2171.95 "
                              "Safari/537.36",
            }
            if post:
                requests.post(
                    webhook_url,
                    headers=headers,
                    json=json_data,
                )
            else:

                requests.get(
                    webhook_url,
                    headers=headers,
                    params=json_data,
                )
        except Exception as e:
            self.__logging.error(f"Error sending results to webhook: {e}")

    def run(self, **kwargs):
        """
        Runs the report.

        :param kwargs: Arguments for the Report module. See below.
        :type kwargs: dict

        :Keyword Arguments:
        * *results* (dict) -- Dictionary containing the results of the scan.
        * *path* (string) -- Path to the report.
        * *mode* (Mode) -- Report mode.
        * *stix* (bool) -- If True, the report will be generated in STIX format.
        * *webhook* (string) -- Webhook to send the report to.
        * *prometheus* (string) -- Prometheus output path.
        """

        self.input(**kwargs)
        assert "path" in self.__input_dict, "Missing output path"
        assert "results" in self.__input_dict, "Missing results list"
        assert "mode" in self.__input_dict, "Missing mode"
        assert "stix" in self.__input_dict, "Missing stix flag"
        if "webhook" not in self.__input_dict or self.__input_dict["webhook"] is None:
            self.__input_dict["webhook"] = ""

        path = self.__input_dict["path"]
        self.__path = Path(path)

        Validator(
            [
                (path, str),
                (self.__input_dict["results"], dict),
                (self.__input_dict["mode"], self.Mode),
                (self.__input_dict["stix"], bool),
                (self.__input_dict["webhook"], str),
                (
                    ""
                    if "prometheus" not in self.__input_dict or not self.__input_dict["prometheus"]
                    else kwargs["prometheus"],
                    str,
                ),
            ]
        )

        if not Path("results").exists():
            self.__logging.debug("Adding result folder...")
            mkdir("results")
        if not Path(f"results{sep}assets").exists():
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
        # get webserver types
        webserver_types = WebserverType().output()
        # this block is needed to prepare the output of the compliance modules
        if any([module in modules for module in ["compare_one", "compare_many"]]):
            module = "compare_one" if "compare_one" in modules else "compare_many"
            for hostname in results:
                if results[hostname].get(module):
                    for sheet in results[hostname][module]:
                        if "mitigation" in results[hostname][module][sheet]:
                            modules[module + "_" + sheet] = ""
                            results[hostname][module + "_" + sheet] = results[hostname][module][sheet]
                        elif "placeholder" in results[hostname][module][sheet]:
                            modules[module + "_" + sheet] = ""
                        else:
                            self.__logging.debug(f"Removing {sheet} from {hostname} because no mitigation was found")
                results[hostname].pop(module, None)
            del modules[module]
        # now, we want to divide raw from mitigations
        for hostname in results:
            webserver_type = webserver_types.get(hostname, "").title()
            for module in results[hostname]:
                raw = results[hostname][module].copy()
                if "mitigation" in raw:
                    del raw["mitigation"]
                for mitigation in rec_search_key(
                        "mitigation", results[hostname][module]
                ):
                    if mitigation is not None:
                        # remove the other mitigation types
                        if webserver_type in mitigation.get("Entry", {}).get("Mitigation", {}):
                            # Remove all the mitigations that don't apply to this configuration
                            to_remove = [el for el in mitigation["Entry"]["Mitigation"] if
                                         el not in ["Textual", webserver_type]]
                            for element in to_remove:
                                del mitigation["Entry"]["Mitigation"][element]
                        results[hostname][
                            module
                        ] = (
                            mitigation.copy()
                        )  # i'm expecting only one mitigation per module, is it ok?
                results[hostname][module]["raw"] = raw
        use_rml = False
        if self.__path.suffix.lower() == ".pdf":
            self.__logging.debug("Using jinja2 to generate RML...")
            use_rml = True
            output_path = f"{output_file.absolute().parent}{sep}{output_file.stem}.rml"
        if len(results) == 0:
            results = {list(self.__input_dict['results'].keys())[i]: '' for i in range(len(self.__input_dict['results']))} # I use that to have the name of the hosts/apk/ipa in the pdf output in case of no vunlerabilities detected
        with open(output_path, "w") as f:
            f.write(
                self.__jinja2__report(
                    mode=self.__input_dict["mode"],
                    modules=list(modules.keys()),
                    results=results,
                    date=datetime.now().replace(microsecond=0),
                    rml=use_rml
                )
            )
            print(results)

        self.__logging.debug("Checking if needs pdf...")
        if self.__path.suffix.lower() == ".pdf":
            self.__logging.debug("Converting to PDF...")
            try:
                xml_path = output_path
                output_path = output_path[:-4] + ".pdf"
                rml2pdf.go(xml_path, output_path)
            except Exception as e:
                self.__logging.error(f"Error converting to PDF: {e}")
                self.__logging.debug("Dumping results used by jinja to file")
                with open(output_path + "-dump.txt", "w") as f:
                    f.write(str(results))

        self.__logging.info(f"Report generated at {output_path}")

        self.__logging.debug("Checks if needs stix...")

        if "stix" in self.__input_dict and self.__input_dict["stix"]:
            stix_output_path = Path(
                f"{output_file.absolute().parent}{sep}stix_{output_file.stem}.json"
            ).absolute()
            results_to_stix = (
                self.__hosts_report_formatter(results)
                if self.__input_dict["mode"] == self.Mode.HOSTS
                else self.__modules_report_formatter(results, modules)
            )
            self.__logging.info("Starting STIX generation...")
            Stix(type_of_analysis=self.__input_dict["mode"].value).build_and_save(
                results_to_stix, modules, str(stix_output_path)
            )
        self.__logging.debug("Checks if needs webhook...")
        if "webhook" in self.__input_dict and self.__input_dict["webhook"]:
            self.__logging.info("Starting webhook...")
            self.__send_webhook(
                self.__input_dict["webhook"],
                results=results,
                modules=modules,
            )
        if 'prometheus' in self.__input_dict and self.__input_dict['prometheus'] != '':
            self.__logging.info("Starting prometheus...")

            output_path_prometheus = f"{output_file.absolute().parent}{sep}{output_file.stem}_prometheus.log" if not \
                self.__input_dict['prometheus'] else self.__input_dict['prometheus']
            Prometheus(results=results, modules=modules).run(output_path_prometheus)


class Prometheus:
    """
    This class generates a prometheus compliant output
    """

    def __init__(self, results, modules):
        self.__logging = Logger("Prometheus")
        Validator(
            [
                (results, dict),
                (modules, dict),
            ]
        )
        self.results = results
        self.modules = modules
        self.output = []

    def generate_output(self):
        """
        This method will generate the output in the form of
        tls_check{vhost=hostname_analyzed,vulnerability=Module_name} 1 if vulnerable, 0 if not
        """
        self.__logging.debug("Generating output...")
        for module in self.modules:
            for host in self.results:
                if module in self.results[host]:
                    self.output.append(f"tls_check{{vhost=\"{host}\",vulnerability=\"{module}\"}} 1")
                else:
                    self.output.append(f"tls_check{{vhost=\"{host}\",vulnerability=\"{module}\"}} 0")

    def run(self, file_name: str):
        self.generate_output()
        with open(file_name, "w") as f:
            self.__logging.debug(f"Writing output in file {file_name}")
            for line in self.output:
                f.write(line + "\n")
        self.__logging.info(f"Prometheus output generated at {file_name}")
