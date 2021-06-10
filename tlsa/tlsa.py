import logging
from pathlib import Path

from utils.logger import Logger, Color
from utils.loader import load_configuration
from utils.configuration import pretty
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
        else:
            raise NotImplementedError("Report type not yet implemented.")

    def __print_module(self, module=None, configs_path=f"configs{sep}modules{sep}"):
        if module:
            pretty(load_configuration(module))
        else:
            all_modules = "\n\t".join(
                [
                    f"{Color.CBEIGE}{Path(f).stem}{Color.ENDC}"
                    for f in listdir(configs_path)
                    if isfile(join(configs_path, f))
                ]
            )
            print(
                f"Here's a list of all the modules available:\n\t{all_modules}"
                f"\nUse \n\t-l module_name\n to read the details."
            )

    def __start_analysis(self, args):
        logging.basicConfig(level=logging.DEBUG if args.verbosity else logging.INFO)
        self.__logging.debug("Started anaylsis with verbosity on.")
        self.__logging.debug("Initializing Core element.")
        config_or_modules = args.configuration
        if args.server:
            Core(
                hostname=args.server,
                configuration=config_or_modules,
                output=args.output,
                output_type=self.__to_report_type(args.output_type),
            )
        elif args.apk:
            raise NotImplementedError("APK not yet implemented.")
        else:  # must be args.list, unless argparse throws error.
            self.__print_module(args.list)
