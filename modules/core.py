from modules.server.testssl_base import Testssl_base
from modules.server.wrappers.testssl import Testssl
from utils.logger import Logger
from utils.validation import Validator
from modules.parse_input_conf import Parser


class Core:
    def __init__(self, hostname: str, configuration: str):
        self.__logging = Logger(self)
        self.__input_dict = {}
        self.__cache = {}
        self.input(configuration=configuration, hostname=hostname)
        self.__cache[configuration] = self.__load_configuration()
        self.__exec()

    def input(self, **kwargs):
        assert "configuration" in kwargs, "Missing configuration."
        assert "hostname" in kwargs, "Missing hostname."
        configuration = kwargs["configuration"]
        hostname = kwargs["hostname"]
        Validator([(configuration, str), (hostname, str)])
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
        self.__logging.debug(
            f"Starting preanalysis testssl with args {testssl_args}..."
        )
        Testssl().run(hostname=self.__input_dict["hostname"], args=testssl_args)
        self.__logging.debug(f"Preanalysis testssl done.")

    def __exec(self):
        configuration_name = self.__input_dict["configuration"]
        parsed_configuration = self.__cache[configuration_name]
        loaded_modules = {}
        loaded_arguments = {}
        testssl_args = []
        results = {}
        self.__logging.debug(f"Loading modules..")
        # loading modules
        for name, module_args in parsed_configuration.items():
            Module, args = module_args
            self.__logging.debug(f"Loading {name}...")
            loaded_modules[name] = Module()
            loaded_arguments[name] = args
            testssl_args = self.__add_testssl_args(loaded_modules[name], testssl_args)
        for name, module in loaded_modules.items():
            args = loaded_arguments[name]
            self.__logging.debug(f"Running {name}...")
            results[name] = module.run(**args)
        # todo: output call
