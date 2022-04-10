from os.path import sep
from pathlib import Path

from modules.configuration.configuration import Configuration
from modules.server.testssl_base import Testssl_base
from modules.server.wrappers.testssl import Testssl
from utils.booleanize import boolean_results
from utils.logger import Logger
from utils.colors import Color
from utils.validation import Validator, is_apk
from modules.parse_input_conf import Parser
import datetime
from enum import Enum
from modules.report import Report as Report_module
from utils.urls import link_sep
from utils.urls import has_wildcard, remove_wildcard
from utils.subdomain_enumeration import enumerate


class Core:
    """
    Core module
    """

    class Report(Enum):
        """
        Enum class for different report types
        """

        HTML = 0
        PDF = 1
        RAW = 2  # todo implement RAW
        ATTACK_TREES = 3  # todo implement attack trees module

    class Analysis(Enum):
        """
        Enum class for different analysis types
        """

        HOST = 0
        APK = 1
        DOMAINS = 2
        CONFIGURATION = 3

    def __init__(
        self,
        hostname_or_path: str or list,
        configuration: str or list,
        output=None,
        output_type=None,
        type_of_analysis=Analysis.HOST,
        to_exclude=None,
        group_by="host",
        apply_fix="",
        openssl_version=None,
        ignore_openssl=False,
        stix=False,
    ):
        """
        :param hostname_or_path: hostname or path to scan
        :type hostname_or_path: str or list
        :param configuration: path to configuration file
        :type configuration: str or list
        :param output: path to output file
        :type output: str or list
        :param output_type: type of output
        :type output_type: str or list
        :param type_of_analysis: type of analysis
        :type type_of_analysis: str or list
        :param to_exclude: list of domains to exclude
        :type to_exclude: str or list
        :param group_by: choose what to group by in the output
        :type group_by: str
        :param apply_fix: apply a fix to the scan
        :type apply_fix: str
        :param openssl_version: version of openssl to use
        :type openssl_version: str
        :param ignore_openssl: ignore openssl version
        :type ignore_openssl: bool
        :param stix: generate stix report
        :type stix: bool
        """
        if to_exclude is None:
            to_exclude = []
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
            to_exclude=to_exclude,
            group_by=group_by,
            apply_fix=apply_fix,
            openssl_version=openssl_version,
            ignore_openssl=ignore_openssl,
            stix=stix,
        )
        self.__cache[configuration] = self.__load_configuration(modules)
        print(self.__cache[configuration])
        
        self.__exec(
            type_of_analysis=self.__input_dict["type_of_analysis"],
            hostname_or_path=self.__input_dict["hostname_or_path"],
            configuration=self.__input_dict["configuration"],
        )
        ''''''
       

    def __string_output_type(self, kwargs_type: Report) -> str:
        """
        Returns a string for the output type

        :param kwargs_type: type of output
        :type kwargs_type: str
        :return: string for the output type
        :rtype: str
        """
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
                (kwargs["to_exclude"], list),
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
                (
                    ""
                    if "apply_fix" not in kwargs or not kwargs["apply_fix"]
                    else kwargs["apply_fix"],
                    str,
                ),
                (kwargs["stix"], bool),
            ]
        )
        kwargs["to_exclude"] = list(map(str.lower, kwargs["to_exclude"]))
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
        """
        Loads the configuration file

        :param modules: list of modules
        :type modules: list
        :return: configuration
        :rtype: dict
        """
        assert "configuration" in self.__input_dict, "Missing configuration."
        self.__logging.debug(
            f"Loading configuration {self.__input_dict['configuration']}"
        )
        return Parser(
            self.__input_dict["configuration"] if not modules else modules
        ).output()

    def __is_testssl(self, module: object) -> bool:
        """
        Checks if the module is a testssl module

        :param module: module to check
        :type module: object
        :return: True if the module is a testssl module
        :rtype: bool
        """
        return isinstance(module, Testssl_base)

    def __add_testssl_args(self, module: Testssl_base, testssl_args: list) -> list:
        """
        Adds testssl arguments from the module

        :param module: module to add arguments from
        :type module: Testssl_base
        :param testssl_args: list of arguments
        :type testssl_args: list
        :return: list of arguments
        :rtype: list

        """
        if self.__is_testssl(module):
            testssl_args += module._arguments
        return testssl_args

    def __conf_analysis(
        self,
        path,
        loaded_modules,
        openssl_version=None,
        ignore_openssl=False,
        online=False,
        port=None,
    ) -> dict:
        """
        Analize the configuration file

        :param path: path to the file
        :type path: str
        :param loaded_modules: loaded modules
        :type loaded_modules: dict
        :param openssl_version: version of OpenSSL
        :type openssl_version: str
        :param ignore_openssl: ignore OpenSSL version
        :type ignore_openssl: bool
        :param online: True if the analysis is done on the internet
        :type online: bool
        :param port: port to use for the connection
        :type port: int
        :return: configuration
        :rtype: dict
        """
        conf = Configuration(path, port=port)
        if self.__input_dict["apply_fix"] != "":
            results = conf.fix(
                loaded_modules,
                online=online,
                openssl=openssl_version,
                ignore_openssl=ignore_openssl,
            )
            if self.__input_dict["apply_fix"] is None:  # differentiate None and ''
                conf.save()
            else:
                conf.save(self.__input_dict["apply_fix"])
        else:
            results = conf.is_vuln(
                loaded_modules, openssl=openssl_version, ignore_openssl=ignore_openssl
            )
        return results

    def __preanalysis_testssl(
        self, testssl_args: list, type_of_analysis: Analysis, hostname: str, port: str
    ):
        """
        Preanalysis of testssl

        :param testssl_args: arguments for testssl
        :type testssl_args: list
        :param type_of_analysis: type of analysis
        :type type_of_analysis: Analysis
        :param hostname: hostname
        :type hostname: str
        :param port: port to use
        :type port: str
        :return: preanalysis
        :rtype: dict
        """
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
                force=True,  # this should solve for multiple scans on the same IP with different ports
            )
            self.__logging.debug(f"Preanalysis testssl done.")

    def __load_modules(self, parsed_configuration: dict) -> (dict, dict, list):
        """
        Loads the modules

        :param parsed_configuration: configuration
        :type parsed_configuration: dict
        :return: loaded modules
        :rtype: tuple
        """

        loaded_modules = {}
        loaded_arguments = {}
        testssl_args = []
        for name, module_args in parsed_configuration.items():
            if name not in self.__input_dict["to_exclude"]:
                Module, args = module_args
                self.__logging.debug(f"Loading {name}...")
                if self.__input_dict["type_of_analysis"] == self.Analysis.APK:
                    assert is_apk(Module), f"The module {name} isn't APK related!"
                else:
                    assert not is_apk(
                        Module
                    ), f"The module {name} isn't Server related!"

                loaded_modules[name] = Module()
                loaded_arguments[name] = args.copy()
                testssl_args = self.__add_testssl_args(
                    loaded_modules[name], testssl_args
                )
            else:
                self.__logging.debug(f"Module {name} excluded, skipping..")
        return loaded_modules, loaded_arguments, testssl_args

    def __run_analysis(
        self,
        loaded_modules: dict,
        type_of_analysis: Analysis,
        hostname_or_path: str,
        loaded_arguments: dict,
        port=None,
    ) -> dict:
        """
        Run the analysis

        :param loaded_modules: loaded modules
        :type loaded_modules: dict
        :param type_of_analysis: type of analysis
        :type type_of_analysis: Analysis
        :param hostname_or_path: hostname or path to the file
        :type hostname_or_path: str
        :param loaded_arguments: arguments for the modules
        :type loaded_arguments: dict
        :param port: port to use
        :type port: str
        :return: results
        :rtype: dict
        """
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

    def __call_output_modules(self, res: dict):

        """
        Call output modules

        :param res: results
        :type res: dict
        :loaded_modules: loaded modules
        :type loaded_modules: dict
        """

        if (
            self.__input_dict["output_type"] == self.Report.HTML
            or self.__input_dict["output_type"] == self.Report.PDF
        ):
            Report_module().run(
                path=self.__input_dict["output"],
                results=res,
                mode=Report_module.Mode.MODULES
                if "group_by" in self.__input_dict
                and self.__input_dict["group_by"] == "module"
                else Report_module.Mode.HOSTS,
                stix=self.__input_dict["stix"],
            )
        self.__logging.debug("Output generated.")

    def __enumerate_hosts(
        self, hostname_or_path: str, type_of_analysis: Analysis
    ) -> str:
        if type_of_analysis in [
            self.Analysis.HOST,
            self.Analysis.DOMAINS,
        ] and has_wildcard(
            hostname_or_path
        ):  # checks if it's a host or a domain list analysis
            # perform enumeration if needed
            self.__logging.info(
                f"Performing subdomain enumeration on {hostname_or_path}.."
            )
            for host in enumerate(remove_wildcard(hostname_or_path)):
                if has_wildcard(host):  # escape wildcard
                    host = remove_wildcard(host)
                yield host
        else:
            yield hostname_or_path

    def __wrap_execution(
        self,
        res: dict,
        domain: str,
        type_of_analysis: Analysis,
        configuration: str,
        port=None,
    ):  # used to wrap the execution so we don't have repeated code
        for host in self.__enumerate_hosts(domain, type_of_analysis):
            if (
                type_of_analysis == self.Analysis.CONFIGURATION
            ):  # we assume there's only one configuration
                # if configuration type. The for loop will only run once.
                # due to the configuration analysis, we need to remove the configuration name and iter in it.
                # i know there's probably a better solution, but today i'm too tired to think about it.
                loaded_modules, raw_res = self.__exec_anaylsis(
                    type_of_analysis, host, configuration, port
                )
                for vhost, value in raw_res.items():  # unpack the results
                    if vhost not in res:
                        res[vhost] = {}
                    res[vhost]["results"] = value.copy()
                    res[vhost][
                        "loaded_modules"
                    ] = loaded_modules  # to make it work report-wise
                    # we need a dict of loaded modules for each vhost
            else:
                if host not in res:
                    res[host] = {}
                (
                    res[host]["loaded_modules"],
                    res[host]["results"],
                ) = self.__exec_anaylsis(type_of_analysis, host, configuration, port)

    def __exec(
        self,
        type_of_analysis: Analysis,
        hostname_or_path: str or list,
        configuration: str,
        port: str = None,
    ):
        """
        Execute the analysis

        :param type_of_analysis: type of analysis
        :type type_of_analysis: Analysis
        :param hostname_or_path: hostname or path to the file
        :type hostname_or_path: str
        :param configuration: configuration
        :type configuration: str
        :param port: port to use
        :type port: str
        """

        res = {}
        if type_of_analysis == self.Analysis.DOMAINS:
            self.__logging.info("Executing multiple domain analysis.")
            for domain in hostname_or_path:
                self.__wrap_execution(
                    res, domain, type_of_analysis, configuration, port
                )
        else:
            self.__wrap_execution(
                res, hostname_or_path, type_of_analysis, configuration, port
            )
        self.__logging.info(f"Generating output..")
        self.__call_output_modules(res)

    def __exec_anaylsis(
        self,
        type_of_analysis: Analysis,
        hostname_or_path: str,
        configuration: str,
        port: str = None,
    ):
        """
        Internal method to execute the analysis

        :param type_of_analysis: type of analysis
        :type type_of_analysis: Analysis
        :param hostname_or_path: hostname or path to the file
        :type hostname_or_path: str
        :param configuration: configuration
        :type configuration: str
        :param port: port to use
        :type port: str
        :return: loaded modules and results
        :rtype: tuple
        """
        self.__logging.info(f"Started analysis on {hostname_or_path}.")
        if type_of_analysis not in [self.Analysis.APK, self.Analysis.CONFIGURATION]:
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
        if type_of_analysis == self.Analysis.CONFIGURATION:
            results = self.__conf_analysis(
                hostname_or_path,
                loaded_modules=loaded_modules,
                openssl_version=self.__input_dict["openssl_version"],
                ignore_openssl=self.__input_dict["ignore_openssl"],
            )  # TODO: better output report
        else:
            self.__preanalysis_testssl(
                testssl_args, type_of_analysis, hostname_or_path, port
            )

            results = self.__run_analysis(
                loaded_modules,
                type_of_analysis,
                hostname_or_path,
                loaded_arguments,
                port,
            )

            if self.__input_dict["apply_fix"]:
                self.__conf_analysis(
                    self.__input_dict["apply_fix"],
                    loaded_modules=self.__remove_useless_modules(
                        raw_results=results, loaded_modules=loaded_modules
                    ),
                    online=True,
                    openssl_version=self.__input_dict["openssl_version"],
                    ignore_openssl=self.__input_dict["ignore_openssl"],
                    port=port,
                )
        self.__logging.info(f"Analysis of {hostname_or_path} done.")
        return loaded_modules, results
        # todo add output attack trees

    def __remove_useless_modules(self, raw_results: dict, loaded_modules: dict) -> dict:
        """
        Remove useless modules from the results

        :param raw_results: raw results
        :type raw_results: dict
        :param loaded_modules: loaded modules
        :type loaded_modules: dict
        :return: results without useless modules
        :rtype: dict
        """

        b_res = boolean_results(modules=loaded_modules, raw_results=raw_results)
        out = {}
        for module, value in loaded_modules.items():
            if module in b_res and b_res[module]:
                out[module] = value
        return out
