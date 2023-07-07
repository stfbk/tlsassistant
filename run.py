import argparse
from argparse import RawTextHelpFormatter

from tlsa.tlsa import Tlsa
from utils.globals import version


class ComplianceAction(argparse.Action):
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        super().__init__(option_strings, dest, nargs, **kwargs)

    def __call__(self, parser, namespace, values, option_string=""):
        if not isinstance(namespace.__getattribute__(self.dest), dict):
            namespace.__setattr__(self.dest, {})
        converters = {
            "false": False,
            "true": True
        }
        dictionary = namespace.__getattribute__(self.dest)
        dictionary[option_string.strip("-")] = converters.get(values[0].lower(), values[0])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="TLSAssistant",
        description="%(prog)s Help",
        formatter_class=RawTextHelpFormatter,  # todo: change the desc
        epilog="https://st.fbk.eu -  Security and Trust, FBK Research Unit",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s v{version}")
    parser.add_argument(
        "-v",
        "--verbosity",
        action="store_true",
        help="increase output verbosity",
        default=False,
    )
    openssl = parser.add_mutually_exclusive_group()
    openssl.add_argument(
        "--openssl",
        "--openssl-version",
        action="store",
        type=str,
        help="Add openSSL version to consider if configuration analysis is asked.",
    )
    openssl.add_argument(
        "--ignore-openssl",
        action="store_true",
        dest="ignore_openssl",
        help="During configuration analysis, ignore openssl version completely.",
    )
    hostname_or_apk = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument(
        "-ot",
        "--output-type",
        action="store",
        type=str,
        choices=["pdf", "html"],
        default=None,
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
    parser.add_argument(
        "--group-by",
        action="store",
        help="Choose how to group results by.",
        choices=["host", "module"],
        default="host",
    )
    hostname_or_apk.add_argument(
        "-s",
        "--server",
        type=str,
        action="store",
        help="The hostname, target of the analysis.",
    )
    hostname_or_apk.add_argument(
        "-f",
        "--file",
        type=str,
        action="store",
        help="The configuration to analyze.",
    )
    hostname_or_apk.add_argument(
        "-d",
        "--domain_file",
        type=str,
        action="store",
        help="The file path which has the hostname to analyze.",
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
    parser.add_argument(
        "--apply-fix",
        dest="apply_fix",
        action="store",
        type=str,
        nargs="?",
        default="",
        help="Apply fix in the current configuration.\n Give a path if using -s.\ni.e."
             "\n\tpython3 run.py -s fbk.eu --apply-fix myconf.conf",
    )
    configurations = parser.add_mutually_exclusive_group()
    configurations.add_argument(
        "-c",
        "--conf",
        "--configuration",
        action="store",
        dest="configuration",
        help="Configuration path.",
        default="default",
    )
    configurations.add_argument(
        "-m",
        "--modules",
        action="store",
        dest="configuration",
        nargs="+",
        help="List of modules to run" "\nFor example\n\t-m breach crime freak",
    )
    parser.add_argument(
        "-e",
        "--exclude",
        action="store",
        dest="exclude",
        nargs="+",
        help="List of modules to exclude" "\nFor example\n\t-e breach crime",
    )
    parser.add_argument(
        "--stix",
        action="store_true",
        help="Generate STIX2 compliant output.",
        default=False,
    )

    parser.add_argument(
        "--guidelines",
        type=str,
        nargs=1,
        action=ComplianceAction,
        dest="compliance_args",
        help="A string containing the names of the guidelines that should be checked in the form: "
             "guideline_version1_version2 in the case of multiple guidelines they should be comma separated. "
             "Use \"list\" for a list of valid strings and \"aliases\" for a list of aliases."
    )

    parser.add_argument(
        "--apache",
        type=str,
        nargs=1,
        action=ComplianceAction,
        default=True,
        dest="compliance_args",
        help="Default to True. If True the output configuration will have apache syntax, if false nginx will be used."
    )
    parser.add_argument(
        "--security",
        type=str,
        nargs=1,
        action=ComplianceAction,
        default=True,
        dest="compliance_args",
        help="Default to True. If False the legacy level priority will be used"
    )

    parser.add_argument(
        "--output_config",
        type=str,
        nargs=1,
        action=ComplianceAction,
        dest="compliance_args",
        help="Where to save the output configuration file, only needed for generate one/many"
    )

    # todo add default aliases configurations for analysis
    # configurations.add_argument()
    args = parser.parse_args()
    print(args)
    tlsa = Tlsa(args)
