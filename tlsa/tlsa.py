import logging
from os import listdir
from os.path import isfile, join, sep
from pathlib import Path

from modules.core import Core
from utils.colors import Color
from utils.configuration import pretty
from utils.loader import load_configuration
from utils.loader import load_list_of_domains
from utils.logger import Logger


class Tlsa:
    def __init__(self, args):
        logging.getLogger("filelock").setLevel(
            logging.ERROR
        )  # remove annoying info messages
        self.args = args
        self.__logging = Logger("TLSA")
        self.__start_analysis(args)

    def __to_report_type(self, string):
        """
        Converts the string to the corresponding report type.

        :param string: the string to convert
        :type string: str
        :return: the converted string
        :rtype: str
        """
        if string == "pdf":
            return Core.Report.PDF
        elif string == "html":
            return Core.Report.HTML
        elif string is None:
            return None
        else:
            raise NotImplementedError("Report type not yet implemented.")

    def __print_module(self, module=None, configs_path=None):
        """
        Prints the module name and the configuration file path.

        :param module: the module name
        :type module: str
        :param configs_path: the path to the configuration file
        :type configs_path: str
        """
        if module:
            pretty(load_configuration(module))
        else:
            if configs_path:
                all_modules = "\n\t".join(
                    [
                        f"{Color.CBEIGE}{Path(f).stem}{Color.ENDC}"
                        for f in listdir(configs_path)
                        if f.endswith(".json") and isfile(join(configs_path, f))
                    ]
                )
            else:
                android_modules = (
                    f"{Color.CGREEN}Android:{Color.ENDC}\n\t"
                    + "\n\t".join(
                        [
                            f"{Color.CBEIGE}{Path(f).stem}{Color.ENDC}"
                            for f in listdir(f"configs{sep}modules{sep}android{sep}")
                            if f.endswith(".json")
                            and isfile(join(f"configs{sep}modules{sep}android{sep}", f))
                        ]
                    )
                )
                server_modules = (
                    f"{Color.CYELLOW}Server:{Color.ENDC}\n\t"
                    + "\n\t".join(
                        [
                            f"{Color.CBEIGE}{Path(f).stem}{Color.ENDC}"
                            for f in listdir(f"configs{sep}modules{sep}server{sep}")
                            if f.endswith(".json")
                            and isfile(join(f"configs{sep}modules{sep}server{sep}", f))
                        ]
                    )
                )
                all_modules = f"{android_modules}\n{server_modules}"

            print(
                f"Here's a list of all the modules available:\n{all_modules}"
                f"\nUse \n\t-l module_name\n to read the details."
            )

    def __start_analysis(self, args):
        """
        Starts the analysis of the TLSA module.

        :param args: the arguments provided to the module
        :type args: argparse.Namespace
        """
        logging.basicConfig(level=logging.DEBUG if args.verbosity else logging.INFO)
        self.__logging.debug("Started anaylsis with verbosity on.")
        self.__logging.debug("Initializing Core element.")
        if isinstance(args.configuration, str) and args.configuration == "default":
            args.configuration = (
                f"default{'_android.json' if args.apk else '_server.json'}"
            )
        config_or_modules = args.configuration
        if args.compliance_args:
            assert "guidelines" in args.compliance_args, "Guideline Argument Missing!"
            all_args=args.compliance_args.copy()
            comp_one_or_many="compare_one" if "," not in all_args['guidelines'] else "compare_many"
            gen_one_or_many="generate_one" if "," not in all_args['guidelines'] else "generate_many"
            args.compliance_args={
                comp_one_or_many:all_args,
                gen_one_or_many:all_args
            }
            
        if args.apply_fix or args.file:
            # checks for openssl and ignore-openssl flag
            if not args.ignore_openssl and not args.openssl:
                raise AssertionError(
                    f"\n{Color.WARNING}OpenSSL is required to fix the TLSA records.{Color.ENDC}"
                    f"\nIgnore the checks with \n\t{Color.CBEIGE}--ignore-openssl{Color.ENDC}\n"
                    f"or insert an openssl version with\n\t{Color.CBEIGE}--openssl [VERSION]{Color.ENDC}"
                )

        if args.server:
            Core(
                hostname_or_path=args.server,
                configuration=config_or_modules,
                output=args.output,
                output_type=self.__to_report_type(args.output_type),
                to_exclude=args.exclude,
                type_of_analysis=Core.Analysis.HOST,
                group_by=args.group_by,
                apply_fix=args.apply_fix,
                stix=args.stix,
                compliance_args=args.compliance_args
            )
        elif args.apk:
            Core(
                hostname_or_path=args.apk,
                configuration=config_or_modules,
                output=args.output,
                output_type=self.__to_report_type(args.output_type),
                to_exclude=args.exclude,
                type_of_analysis=Core.Analysis.APK,
                group_by=args.group_by,
                stix=args.stix,
            )
        elif args.domain_file:
            Core(
                hostname_or_path=load_list_of_domains(args.domain_file),
                configuration=config_or_modules,
                output=args.output,
                output_type=self.__to_report_type(args.output_type),
                to_exclude=args.exclude,
                type_of_analysis=Core.Analysis.DOMAINS,
                group_by=args.group_by,
                stix=args.stix,
            )
        elif args.file:
            if isinstance(args.configuration, list):
                self.__logging.warning(
                    "Ignoring module list. Try to exclude the modules with -e module1 module2"
                )
            Core(
                hostname_or_path=args.file,
                configuration="default_file.json",
                output=args.output,
                output_type=self.__to_report_type(args.output_type),
                type_of_analysis=Core.Analysis.CONFIGURATION,
                to_exclude=args.exclude,
                group_by=args.group_by,
                apply_fix=args.apply_fix,
                stix=args.stix,
                openssl_version=args.openssl,
                ignore_openssl=args.ignore_openssl,
            )
        elif any(module in ["generate_one", "generate_many"] for module in args.configuration):
            Core(
                hostname_or_path="placeholder",
                configuration=config_or_modules,
                output=args.output,
                output_type=self.__to_report_type(args.output_type),
                type_of_analysis=Core.Analysis.COMPLIANCE,
                to_exclude=args.exclude,
                group_by=args.group_by,
                apply_fix=args.apply_fix,
                stix=args.stix,
                openssl_version=args.openssl,
                ignore_openssl=args.ignore_openssl,
                compliance_args=args.compliance_args
            )

        else:  # must be args.list, unless argparse throws error.
            self.__print_module(args.list)
