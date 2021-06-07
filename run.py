import argparse
from argparse import RawTextHelpFormatter
from tlsa.tlsa import Tlsa

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="TLSAssistant Help",
        formatter_class=RawTextHelpFormatter,  # todo: change the desc
        epilog="https://st.fbk.eu - Security and Trust Unit",
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
        action="store_const",
        dest="configuration",
        help="Configuration path.",
        const="default.json",
    )
    configurations.add_argument(
        "-l",
        "--list",
        action="store",
        dest="configuration",
        nargs="+",
        help="List of modules to run" "\nFor example\n\t-l breach crime freak",
    )
    # todo add default aliases configurations for analysis
    # configurations.add_argument()
    args = parser.parse_args()
    tlsa = Tlsa(args)
