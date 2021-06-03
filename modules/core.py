from modules.server.testssl_base import Testssl_base
from modules.server.wrappers.testssl import Testssl
from utils.logger import Logger
from utils.validation import Validator
from modules.parse_input_conf import Parser
import datetime
from enum import Enum
from modules.report import Report as Report_module


class Core:
    class Report(Enum):
        HTML = 0
        PDF = 1
        RAW = 2  # todo implement RAW
        ATTACK_TREES = 3  # todo implement attack trees module

    def __init__(
        self, hostname: str, configuration: str, output=None, output_type=None
    ):
        self.__logging = Logger("Core")
        self.__input_dict = {}
        self.__cache = {}
        self.input(
            configuration=configuration,
            hostname=hostname,
            output=output,
            output_type=output_type,
        )
        self.__cache[configuration] = self.__load_configuration()
        self.__exec()

    def __string_output_type(self, kwargs_type: Report) -> str:
        return f"{str(kwargs_type.name).lower()}"

    def input(self, **kwargs):
        assert "configuration" in kwargs, "Missing configuration."
        assert (
            "hostname" in kwargs
        ), "Missing hostname."  # todo: facultative hostname, we should use configs sometimes

        # validate
        Validator(
            [
                (kwargs["configuration"], str),
                (kwargs["hostname"], str),
                (
                    self.Report.HTML if "output_type" not in kwargs or not kwargs['output_type'] else kwargs["output_type"],
                    self.Report,
                ),
                # can be none
                (
                    '' if "output" not in kwargs or not kwargs['output'] else kwargs["output"],
                    str,
                ),  # can be none
            ]
        )

        # set outputfilename if not already set
        if "output" not in kwargs or not kwargs["output"]:  # if not output
            file_name = datetime.datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
        else:
            file_name = kwargs["output"]

        # if not output type, just parse it from the file name
        if "output_type" not in kwargs or not kwargs["output_type"]:
            if file_name.lower().endswith(".pdf"):
                kwargs["output_type"] = self.Report.PDF
            elif file_name.lower().endswith(".html"):
                kwargs["output_type"] = self.Report.HTML
            elif file_name.lower().endswith(".raw"):
                kwargs["output_type"] = self.Report.RAW
            else:
                kwargs["output_type"] = self.Report.HTML  # or default HTML

        ext = self.__string_output_type(kwargs["output_type"])  # tostring

        kwargs["output"] = f"{file_name}.{ext}"  # final file name

        self.__input_dict = kwargs

    def __load_configuration(self):
        assert "configuration" in self.__input_dict, "Missing configuration."
        self.__logging.debug(
            f"Loading configuration {self.__input_dict['configuration']}"
        )
        return Parser(self.__input_dict["configuration"]).output()

    def __is_testssl(self, module: object) -> bool:
        return isinstance(module, Testssl_base)

    def __add_testssl_args(self, module: Testssl_base, testssl_args: list) -> list:
        if self.__is_testssl(module):
            testssl_args += module._arguments
        return testssl_args

    def __preanalysis_testssl(self, testssl_args: list):
        if testssl_args:
            self.__logging.debug(
                f"Starting preanalysis testssl with args {testssl_args}..."
            )
            Testssl().run(hostname=self.__input_dict["hostname"], args=testssl_args)
            self.__logging.debug(f"Preanalysis testssl done.")

    def __load_modules(self, parsed_configuration: dict) -> (dict, dict, list):
        loaded_modules = {}
        loaded_arguments = {}
        testssl_args = []
        for name, module_args in parsed_configuration.items():
            Module, args = module_args
            self.__logging.debug(f"Loading {name}...")
            loaded_modules[name] = Module()
            loaded_arguments[name] = args
            testssl_args = self.__add_testssl_args(loaded_modules[name], testssl_args)
        return loaded_modules, loaded_arguments, testssl_args

    def __run_analysis(self, loaded_modules: dict, loaded_arguments: dict) -> dict:
        results = {}
        for name, module in loaded_modules.items():
            if "hostname" not in loaded_arguments[name]:
                loaded_arguments[name]["hostname"] = self.__input_dict["hostname"]
            args = loaded_arguments[name]
            self.__logging.debug(f"Running {name}...")
            results[name] = module.run(**args)

        return results

    def __call_output_modules(self, loaded_modules: dict, results: dict):
        if (
            self.__input_dict["output_type"] == self.Report.HTML
            or self.__input_dict["output_type"] == self.Report.PDF
        ):
            Report_module().run(
                path=self.__input_dict["output"],
                modules=loaded_modules,
                results=results,
            )
        self.__logging.debug("Output generated.")

    def __exec(self):
        configuration_name = self.__input_dict["configuration"]
        parsed_configuration = self.__cache[configuration_name]

        self.__logging.debug(f"Loading modules..")
        # loading modules
        loaded_modules, loaded_arguments, testssl_args = self.__load_modules(
            parsed_configuration
        )

        # preanalysis if needed
        self.__preanalysis_testssl(testssl_args)

        results = self.__run_analysis(loaded_modules, loaded_arguments)

        self.__call_output_modules(loaded_modules, results)
        # todo add output attack trees
