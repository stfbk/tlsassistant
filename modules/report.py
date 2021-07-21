from enum import Enum
from os import mkdir
from pathlib import Path
from utils.booleanize import boolean_results

from utils.validation import Validator
from utils import md
from datetime import datetime
from os.path import sep
from utils.logger import Logger
from utils.prune import pruner


class Report:
    """
    Output Module that generates the report.

    """

    class Mode(Enum):
        """
        Enum for the report mode.
        """

        DEFAULT = 0
        SCOREBOARD = 1

    def __init__(self):
        self.__input_dict = {}
        self.__path = ""
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
        * *scoreboard* (bool) -- If true, generates a scoreboard.
        """
        self.__input_dict = kwargs

    def __get_default(self, output):
        """
        Generates the default report.

        :param output: Output list.
        :type output: list
        :return: Output list.
        :rtype: list

        """

        v = Validator()
        for hostname_or_path in self.__input_dict["results"]:
            res = self.__input_dict["results"][hostname_or_path]
            raw_results = res["results"]
            modules = res["loaded_modules"]
            v.dict(raw_results)
            v.string(hostname_or_path)
            v.dict(modules)
            self.__logging.debug("Added headers...")
            raw_results = pruner(raw_results)
            dt_string = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            output += [
                md.italic(f"{dt_string} - {hostname_or_path}"),
                md.title("Modules used", level=md.H2),
                ", ".join([md.italic(module) for module in modules]),
                md.title("Vulnerabilities found", level=md.H2),
            ]

            self.__logging.debug("Recursive parsing...")
            output.append(md.recursive_parsing(raw_results, md.H1, bold_instead=True))

            self.__logging.debug("Recursive parsing done.")
            output.append("\n")
            output.append(md.line())
        return output

    def __get_scoreboard(self, output):
        """
        Generates the scoreboard report.

        :param output: Output list.
        :type output: list
        :return: Output list.
        :rtype: list
        """
        self.__logging.info(f"Generating Scoreboard..")
        v = Validator()
        once = False
        dt_string = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        output.append(md.italic(f"{dt_string}"))
        output.append("\n")
        for hostname_or_path in self.__input_dict["results"]:
            res = self.__input_dict["results"][hostname_or_path]
            raw_results = res["results"]
            modules = res["loaded_modules"]
            v.dict(raw_results)
            v.string(hostname_or_path)
            v.dict(modules)
            raw_results = pruner(raw_results)  # remove useless data
            self.__logging.debug("Added headers...")
            if not once:
                partial = [md.table.wrap("  ")]
                for module in modules:
                    partial.append(md.table.title(module.replace("_", " ")))
                once = True
                output.append(f"|{''.join(partial)}|")

            partial = [md.table.bold(f"{hostname_or_path}")]

            bres = boolean_results(modules, raw_results)

            for module in modules:
                partial.append(md.table.wrap("❌" if bres[module] else "✅"))
            output.append(f"|{''.join(partial)}|")
        output.append("\n")
        output.append(md.line())
        return output

    def run(self, **kwargs):
        """
        Runs the report.

        :param kwargs: Arguments for the Report module. See below.
        :type kwargs: dict

        :Keyword Arguments:
        * *results* (dict) -- Dictionary containing the results of the scan.
        * *path* (string) -- Path to the report.
        * *mode* (Mode) -- Report mode.
        * *scoreboard* (bool) -- If true, generates a scoreboard.
        """

        self.input(**kwargs)
        if "path" not in self.__input_dict:
            raise AssertionError("Missing output path")
        if "results" not in self.__input_dict:
            raise AssertionError("Missing results list")
        # if "hostname_or_path" not in self.__input_dict:
        #    raise AssertionError("Missing hostname of the server or path of apk")

        path = self.__input_dict["path"]
        self.__path = Path(path)

        Validator([(path, str)])
        output = [
            md.title("TLSA Analysis"),
            "\n",
        ]
        output = (
            self.__get_scoreboard(output)
            if "mode" in self.__input_dict
            and self.__input_dict["mode"] == self.Mode.SCOREBOARD
            else self.__get_default(output)
        )
        if not Path("results").exists():
            self.__logging.debug("Adding result folder...")
            mkdir("results")

        output_file = Path(f"results{sep}{self.__path.stem}.html")
        self.__logging.debug("Starting MD to HTML...")
        output_path = output_file.absolute()
        options = [
            "break-on-newline",
            "fenced-code-blocks",
            "code-friendly",
            "cuddled-lists",
        ]
        if (
            "mode" in self.__input_dict
            and self.__input_dict["mode"] == self.Mode.SCOREBOARD
        ):
            options.append("wiki-tables")
        try:
            md.md_to_html(
                options,
                "\n".join(output),
                output_file=str(output_file.absolute()),
                css_file=f"dependencies{sep}typora-mo-theme{sep}mo.css",
            )
        except AssertionError as a:
            self.__logging.warning(
                f"Error in report generation: {a}. Removing cuddled-lists addon..."
            )
            options.remove("cuddled-lists")
            md.md_to_html(
                options,
                "\n".join(output),
                output_file=str(output_file.absolute()),
                css_file=f"dependencies{sep}typora-mo-theme{sep}mo.css",
            )

        self.__logging.debug("Checking if needs pdf...")

        if self.__path.suffix.lower() == ".pdf":
            output_path = f"{output_file.absolute().parent}{sep}{output_file.stem}.pdf"
            self.__logging.debug("Starting HTML to PDF...")
            md.html_to_pdf(str(output_file.absolute()), output_path)
        self.__logging.info(f"Report generated at {output_path}")
        # todo: add PDF library
