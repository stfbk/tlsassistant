from os.path import sep
from pathlib import Path

from modules.server.testssl_base import Testssl_base
from modules.server.wrappers.testssl import Testssl
from utils.logger import Logger
from utils.colors import Color
from utils.validation import Validator, is_apk
from modules.parse_input_conf import Parser
import datetime
from enum import Enum
from modules.report import Report as Report_module
from utils.urls import link_sep


class Core:
    class Report(Enum):
        HTML = 0
        PDF = 1
        RAW = 2  # todo implement RAW
        ATTACK_TREES = 3  # todo implement attack trees module

    class Analysis(Enum):
        HOST = 0
        APK = 1
        DOMAINS = 2

    def __init__(
        self,
        hostname_or_path: str or list,
        configuration: str or list,
        output=None,
        output_type=None,
        type_of_analysis=Analysis.HOST,
    ):
        self.__logging = Logger("Core")
        self.__input_dict = {}
        self.__cache = {}
        modules = None
        if isinstance(configuration, list):  # if modules as argument
            modules = configuration
            configuration = "modules_list"
        self.input(
            configuration=configuration,
            hostname_or_path=hostname_or_path,
            output=output,
            output_type=output_type,
            type_of_analysis=type_of_analysis,
        )
        self.__cache[configuration] = self.__load_configuration(modules)
        self.__exec(
            type_of_analysis=self.__input_dict["type_of_analysis"],
            hostname_or_path=self.__input_dict["hostname_or_path"],
            configuration=self.__input_dict["configuration"],
        )

    def __string_output_type(self, kwargs_type: Report) -> str:
        return f"{str(kwargs_type.name).lower()}"

    def input(self, **kwargs):
        assert "configuration" in kwargs, "Missing configuration."
        assert (
            "hostname_or_path" in kwargs
        ), "Missing hostname."  # todo: facultative hostname, we should use configs sometimes

        # validate
        Validator(
            [
                (kwargs["configuration"], str),
                (kwargs["hostname_or_path"], (str, list)),
                (
                    self.Report.HTML
                    if "output_type" not in kwargs or not kwargs["output_type"]
                    else kwargs["output_type"],
                    self.Report,
                ),
                # can be none
                (
                    ""
                    if "output" not in kwargs or not kwargs["output"]
                    else kwargs["output"],
                    str,
                ),  # can be none
                (kwargs["type_of_analysis"], self.Analysis),
            ]
        )

        # set outputfilename if not already set
        if "output" not in kwargs or not kwargs["output"]:  # if not output
            file_name = datetime.datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
            fl = str(Path(file_name).absolute()).lower()
        else:
            fl = Path(kwargs["output"])
            file_name = f"{fl.absolute().parent}{sep}{fl.absolute().stem}"
            fl = str(Path(kwargs["output"]).absolute()).lower()

        # if not output type, just parse it from the file name
        if "output_type" not in kwargs or not kwargs["output_type"]:
            if fl.endswith(".pdf"):
                kwargs["output_type"] = self.Report.PDF
            elif fl.endswith(".html"):
                kwargs["output_type"] = self.Report.HTML
            elif fl.endswith(".raw"):
                kwargs["output_type"] = self.Report.RAW
            else:
                kwargs["output_type"] = self.Report.HTML  # or default HTML

        ext = self.__string_output_type(kwargs["output_type"])  # tostring

        kwargs["output"] = f"{file_name}.{ext}"  # final file name

        self.__input_dict = kwargs

    def __load_configuration(self, modules):
        assert "configuration" in self.__input_dict, "Missing configuration."
        self.__logging.debug(
            f"Loading configuration {self.__input_dict['configuration']}"
        )
        return Parser(
            self.__input_dict["configuration"] if not modules else modules
        ).output()

    def __is_testssl(self, module: object) -> bool:
        return isinstance(module, Testssl_base)

    def __add_testssl_args(self, module: Testssl_base, testssl_args: list) -> list:
        if self.__is_testssl(module):
            testssl_args += module._arguments
        return testssl_args

    def __preanalysis_testssl(
        self, testssl_args: list, type_of_analysis: Analysis, hostname: str, port: str
    ):
        if testssl_args and (
            type_of_analysis == self.Analysis.HOST
            or type_of_analysis == self.Analysis.DOMAINS
        ):
            self.__logging.debug(
                f"Starting preanalysis testssl with args {testssl_args}..."
            )
            Testssl().run(
                hostname=f"{hostname}:{port}",
                args=testssl_args,
            )
            self.__logging.debug(f"Preanalysis testssl done.")

    def __load_modules(self, parsed_configuration: dict) -> (dict, dict, list):
        loaded_modules = {}
        loaded_arguments = {}
        testssl_args = []
        for name, module_args in parsed_configuration.items():
            Module, args = module_args
            self.__logging.debug(f"Loading {name}...")
            if self.__input_dict["type_of_analysis"] == self.Analysis.APK:
                assert is_apk(Module), f"The module {name} isn't APK related!"
            else:
                assert not is_apk(Module), f"The module {name} isn't Server related!"

            loaded_modules[name] = Module()
            loaded_arguments[name] = args
            testssl_args = self.__add_testssl_args(loaded_modules[name], testssl_args)
        return loaded_modules, loaded_arguments, testssl_args

    def __run_analysis(
        self,
        loaded_modules: dict,
        type_of_analysis: Analysis,
        hostname_or_path: str,
        loaded_arguments: dict,
        port=None,
    ) -> dict:
        results = {}
        if type_of_analysis != self.Analysis.APK:  # server analysis
            hostname_or_path_type = "hostname"
        else:  # android analysis
            hostname_or_path_type = "path"
        for name, module in loaded_modules.items():
            if hostname_or_path_type not in loaded_arguments[name]:
                loaded_arguments[name][hostname_or_path_type] = hostname_or_path
            args = loaded_arguments[name]
            if type_of_analysis != self.Analysis.APK:  # server analysis
                args["port"] = port  # set the port
            self.__logging.info(f"{Color.CBEIGE}Running {name} module...")
            results[name] = module.run(**args)

        return results

    def __call_output_modules(self, res: dict, hostname_or_path: str):
        if (
            self.__input_dict["output_type"] == self.Report.HTML
            or self.__input_dict["output_type"] == self.Report.PDF
        ):
            Report_module().run(
                path=self.__input_dict["output"],
                results=res,
                hostname_or_path=hostname_or_path,
            )
        self.__logging.debug("Output generated.")

    def __exec(
        self,
        type_of_analysis: Analysis,
        hostname_or_path: str or list,
        configuration: str,
        port: str = None,
    ):
        res = {}
        if type_of_analysis == self.Analysis.DOMAINS:
            self.__logging.info("Executing multiple domain analysis.")
            for domain in hostname_or_path:
                if domain not in res:
                    res[domain] = {}
                (
                    res[domain]["loaded_modules"],
                    res[domain]["results"],
                ) = self.__exec_anaylsis(type_of_analysis, domain, configuration)
        else:
            if hostname_or_path not in res:
                res[hostname_or_path] = {}
            (
                res[hostname_or_path]["loaded_modules"],
                res[hostname_or_path]["results"],
            ) = self.__exec_anaylsis(type_of_analysis, hostname_or_path, configuration)
        self.__logging.info(f"Generating output..")
        self.__call_output_modules(
            res,
            hostname_or_path=hostname_or_path,
        )

    def __exec_anaylsis(
        self,
        type_of_analysis: Analysis,
        hostname_or_path: str,
        configuration: str,
        port: str = None,
    ):
        self.__logging.info(f"Started analysis on {hostname_or_path}.")
        if type_of_analysis != self.Analysis.APK:
            hostname_or_path, port = link_sep(hostname_or_path)
        configuration_name = configuration
        self.__logging.info(f"Loading configuration {configuration_name} ..")
        parsed_configuration = self.__cache[configuration_name]

        self.__logging.info(f"Loading modules..")
        # loading modules
        loaded_modules, loaded_arguments, testssl_args = self.__load_modules(
            parsed_configuration
        )

        # preanalysis if needed
        self.__logging.info(f"Running analysis..")
        self.__preanalysis_testssl(
            testssl_args, type_of_analysis, hostname_or_path, port
        )

        results = self.__run_analysis(
            loaded_modules, type_of_analysis, hostname_or_path, loaded_arguments, port
        )
        self.__logging.info(f"Analysis of {hostname_or_path} done.")

        return loaded_modules, results
        # todo add output attack trees
