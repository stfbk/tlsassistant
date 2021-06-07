import logging
from utils.logger import Logger
from modules.core import Core


class Tlsa:
    def __init__(self, args):
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
