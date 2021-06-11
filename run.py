import argparse
from argparse import RawTextHelpFormatter
from tlsa.tlsa import Tlsa

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="TLSAssistant",
        description="%(prog)s Help",
        formatter_class=RawTextHelpFormatter,  # todo: change the desc
        epilog="https://st.fbk.eu -  Security and Trust, FBK Research Unit",
    )
    parser.add_argument(
        "--version", action="version", version="%(prog)s v2 alpha closed release"
    )
    parser.add_argument(
        "-v",
        "--verbosity",
        action="store_true",
        help="increase output verbosity",
        default=False,
    )

    hostname_or_apk = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument(
        "-ot",
        "--output-type",
        action="store",
        type=str,
        choices=["pdf", "html"],
        default="html",
        help="The type of the report output.\nOutput type can be omitted and can be obtained"
        " by --output extension.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        action="store",
        help="Set report path.",
        default=None,
    )
    hostname_or_apk.add_argument(
        "-s",
        "--server",
        type=str,
        action="store",
        help="The hostname, target of the analysis.",
    )
    hostname_or_apk.add_argument(
        "-l",
        "--list",
        nargs="?",
        help="List all modules or print an help of a module.\nFor Example\n-l freak",
        default="",
    )
    hostname_or_apk.add_argument(
        "-a",
        "--apk",
        type=str,
        action="store",
        help="The apk path, target of the analysis.",
    )
    configurations = parser.add_mutually_exclusive_group()
    configurations.add_argument(
        "-c" "--conf",
        "--configuration",
        action="store",
        dest="configuration",
        help="Configuration path.",
        default="default.json",
    )
    configurations.add_argument(
        "-m",
        "--modules",
        action="store",
        dest="configuration",
        nargs="+",
        help="List of modules to run" "\nFor example\n\t-m breach crime freak",
    )
    # todo add default aliases configurations for analysis
    # configurations.add_argument()
    args = parser.parse_args()
    tlsa = Tlsa(args)
