import logging
from pathlib import Path

from utils.logger import Logger
from utils.colors import Color
from utils.loader import load_configuration
from utils.configuration import pretty
from utils.loader import load_list_of_domains
from modules.core import Core
from os import listdir
from os.path import isfile, join, sep


class Tlsa:
    def __init__(self, args):
        logging.getLogger("filelock").setLevel(
            logging.ERROR
        )  # remove annoying info messages
        self.args = args
        self.__logging = Logger("TLSA")
        self.__start_analysis(args)

    def __to_report_type(self, string):
        if string == "pdf":
            return Core.Report.PDF
        elif string == "html":
            return Core.Report.HTML
        elif string is None:
            return None
        else:
            raise NotImplementedError("Report type not yet implemented.")

    def __print_module(self, module=None, configs_path=None):
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
        logging.basicConfig(level=logging.DEBUG if args.verbosity else logging.INFO)
        self.__logging.debug("Started anaylsis with verbosity on.")
        self.__logging.debug("Initializing Core element.")
        if isinstance(args.configuration, str) and args.configuration == "default":
            args.configuration = (
                f"default{'_android.json' if args.apk else '_server.json'}"
            )
        config_or_modules = args.configuration
        if args.server:
            Core(
                hostname_or_path=args.server,
                configuration=config_or_modules,
                output=args.output,
                output_type=self.__to_report_type(args.output_type),
                type_of_analysis=Core.Analysis.HOST,
                scoreboard=args.scoreboard,
            )
        elif args.apk:
            Core(
                hostname_or_path=args.apk,
                configuration=config_or_modules,
                output=args.output,
                output_type=self.__to_report_type(args.output_type),
                type_of_analysis=Core.Analysis.APK,
                scoreboard=args.scoreboard,
            )
        elif args.domain_file:
            Core(
                hostname_or_path=load_list_of_domains(args.domain_file),
                configuration=config_or_modules,
                output=args.output,
                output_type=self.__to_report_type(args.output_type),
                type_of_analysis=Core.Analysis.DOMAINS,
                scoreboard=args.scoreboard,
            )

        else:  # must be args.list, unless argparse throws error.
            self.__print_module(args.list)
