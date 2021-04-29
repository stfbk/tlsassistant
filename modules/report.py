from os import mkdir
from pathlib import Path
from markdown2 import markdown

from utils.validation import Validator
from utils import md
from datetime import datetime
from os.path import sep


class Report:
    def __init__(self):
        self.__input_dict = {}
        self.__path = ""

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
        Validator([
            (path, str),
            (modules, list),
            (raw_results, list)
        ])

        self.__path = Path(path)
        dt_string = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

        output = [
            md.title("TLSA Analysis"),
            md.line(),
            md.italic(dt_string),
            md.title("Modules used", level=md.H2),
            ", ".join([md.italic(module) for module in modules]),
            md.title("Vulnerabilities found", level=md.H2)

        ]
        for name, vuln in raw_results.items():
            output.append(md.title(name, level=md.H3))
            for key, value in vuln:
                output.append(md.bold(key))
                output.append(md.italic(value) if 'code' in key else md.multiline_code(value))
        if not Path("results").exists():
            mkdir("results")
        # todo: HTML mandatory, needs deletion
        md.md_to_html(['break-on-newline', 'fenced-code-blocks'],
                      "\n".join(output),
                      output_file=f"results{sep}results.html",
                      css_file=f'depdendencies{sep}typora-mo-theme{sep}mo.css')
        # todo: add PDF library
