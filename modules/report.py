from os import mkdir
from pathlib import Path

from utils.validation import Validator
from utils import md
from datetime import datetime
from os.path import sep
from utils.logger import Logger


class Report:
    def __init__(self):
        self.__input_dict = {}
        self.__path = ""
        self.__logging = Logger("Report")

    def input(self, **kwargs):
        self.__input_dict = kwargs

    def run(self, **kwargs):
        self.input(**kwargs)
        if "path" not in self.__input_dict:
            raise AssertionError("Missing output path")
        if "modules" not in self.__input_dict:
            raise AssertionError("Missing modules list")
        if "results" not in self.__input_dict:
            raise AssertionError("Missing results list")

        path = self.__input_dict["path"]
        modules = self.__input_dict["modules"]
        raw_results = self.__input_dict["results"]
        Validator([(path, str), (modules, dict), (raw_results, dict)])

        self.__path = Path(path)
        dt_string = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

        self.__logging.debug("Added headers...")
        output = [
            md.title("TLSA Analysis"),
            md.line(),
            md.italic(dt_string),
            md.title("Modules used", level=md.H2),
            ", ".join([md.italic(module) for module in modules]),
            md.title("Vulnerabilities found", level=md.H2),
        ]
        self.__logging.debug("Recursive parsing...")
        output.append(md.recursive_parsing(raw_results, md.H1, bold_instead=True))

        self.__logging.debug("Recursive parsing done.")
        if not Path("results").exists():
            self.__logging.debug("Adding result folder...")
            mkdir("results")

        output_file = Path(f"results{sep}{self.__path.stem}.html")
        self.__logging.debug("Starting MD to HTML...")
        output_path = output_file.absolute()

        md.md_to_html(
            [
                "break-on-newline",
                "fenced-code-blocks",
                "code-friendly",
                "cuddled-lists",
            ],
            "\n".join(output),
            output_file=output_file.absolute(),
            css_file=f"dependencies{sep}typora-mo-theme{sep}mo.css",
        )

        self.__logging.debug("Checking if needs pdf...")

        if self.__path.suffix.lower() == ".pdf":
            output_path = f"{output_file.absolute().parent}{sep}{output_file.stem}.pdf"
            self.__logging.debug("Starting HTML to PDF...")
            md.html_to_pdf(str(output_file.absolute()), output_path)
        self.__logging.info(f"Report generated at {output_path}")
        # todo: add PDF library
