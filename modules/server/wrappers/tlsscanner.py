import logging
import re
import subprocess
import sys
from os import devnull, sep
from collections import defaultdict

from utils.urls import url_strip
from utils.validation import Validator


class Parser:
    """
    Class used to parse TLS-Scanner results.
    """

    def __init__(self, to_parse: dict):
        """
        Init method.
        :param to_parse: Raw JSON output of TLS-Scanner, given as a python dict.
        :type to_parse: dict
        """
        self.__results = to_parse
        self.__output = {}
        self.__ip_output = {}
        self.__parse()

    def __escape_output(self, output):
        # Thanks to Stack Overflow
        # https://stackoverflow.com/questions/14693701/how-can-i-remove-the-ansi-escape-sequences-from-a-string-in-python
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        output = ansi_escape.sub('', output)
        return output

    def __parse(self):  # parse method
        output = self.__escape_output(self.__results)
        output = output.split("\n")
        '''
        report = {
            "ALPACA":{
                "Result" : "",
                "Details" : {},
            },
            "Padding Oracle":{
                "Result" : "",
                "Details" : {}
            },
            "Raccoon" : {
                "Result" : ""
            },
            [...]
        }'''
        report = defaultdict(dict)

        alpaca_details = {}
        padding_oracle_details = {}
        direct_raccoon_details = {}
        hostname = ""
        for i in range(0, len(output)):
            if "Report for" in output[i]:
                hostname = output[i].split(" ")[-1]
            elif "Attack Vulnerabilities" in output[i]:
                j = i + 1
                while output[j] != "------------------------------------------------------------":
                    j += 1
                vulns = output[i+2:j-1]

                for vuln in vulns:
                    if ":" in vuln:
                        vuln, res = vuln.split(" : ", 1)
                        vuln = vuln.replace("\t", "").strip()
                        report[vuln]["Result"] = res
                i = j  # Skip lines

            elif "Alpaca Details" in output[i]:
                j = i + 1
                while output[j] != "------------------------------------------------------------":
                    j += 1
                alpaca_details_temp = output[i+2:j-1]
                for detail in alpaca_details_temp:
                    detail, res = detail.split(" : ", 1)
                    detail = detail.replace("\t", "")
                    if "Strict ALPN" == detail:
                        alpaca_details["Strict ALPN"] = res
                    elif "Strict SNI" == detail:
                        alpaca_details["Strict SNI"] = res
                    elif "ALPACA Mitigation" == detail:
                        alpaca_details["ALPACA Mitigation"] = res
                i = j  # Skip lines

            elif "Padding Oracle Details" in output[i] and report["Padding Oracle"]["Result"] == "vulnerable":
                j = i + 1
                while output[j] != "------------------------------------------------------------":
                    j += 1
                padding_oracle_details_temp = output[i+2:j-1]
                for detail in padding_oracle_details_temp:
                    detail = detail.split("|")
                    name = ('-'.join(detail[0].split("\t")[2:])).strip()
                    behaviour_difference = detail[1].strip()
                    result = detail[2].strip()

                    if "<" in detail[3].strip():
                        P = float(detail[3].strip()[4:])
                    else:
                        P = float(detail[3].strip()[3:])

                    padding_oracle_details[name] = {
                        'Behaviour': behaviour_difference,
                        'Result': result,
                        'Confidence': P
                    }
                i = j  # Skip lines

            elif "Direct Raccoon Results" in output[i] and report["Direct Raccoon"]["Result"] == "vulnerable":
                j = i + 1
                while output[j] != "------------------------------------------------------------":
                    j += 1
                direct_raccoon_details_temp = output[i+2:j-1]
                for detail in direct_raccoon_details_temp:
                    detail = detail.split("|")
                    name = detail[0].replace("\t", "-").strip()
                    behaviour_difference = detail[1].strip()
                    result = detail[2].strip()
                    if "<" in detail[3].strip():
                        P = float(detail[3].strip()[4:])
                    else:
                        P = float(detail[3].strip()[3:])
                    direct_raccoon_details[name] = {
                        'Behaviour': behaviour_difference,
                        'Result': result,
                        'Confidence': P
                    }
                i = j  # Skip lines
        if "Raccoon" not in report:
            report["Raccoon"] = {}
        if "Result" not in report["Raccoon"]:
            report["Raccoon"]["Result"] = "not vulnerable"
        if "Direct Raccoon" not in report:
            report["Direct Raccoon"] = {}
        if "Result" not in report["Direct Raccoon"]:
            report["Direct Raccoon"]["Result"] = "not vulnerable"
        if "Details" not in report["Direct Raccoon"]:
            report["Direct Raccoon"]["Details"] = {}

        report["Padding Oracle"]["Details"] = padding_oracle_details
        report["ALPACA"]["Details"] = alpaca_details
        report["Direct Raccoon"]["Details"] = direct_raccoon_details
        report["Raccoon"]["vulnToRaccoon"] = report["Raccoon"]["Result"]
        report["Raccoon"]["Result"] = 'vulnerable' if (
            report["Raccoon"]["Result"] == 'vulnerable' or report["Direct Raccoon"]["Result"] == 'vulnerable') else 'not vulnerable'
        report["Raccoon"]["vulnToDirectRaccoon"] = report["Direct Raccoon"]["Result"]
        report["Raccoon"]["Details"] = report["Direct Raccoon"]["Details"]
        report.pop("Direct Raccoon", None)

        self.__output = {hostname: report}

    def output(self) -> (dict, dict):
        """
        Output.
        :return: returns parsed cache dicts.
        :rtype: tuple of dict
        """
        return self.__output, self.__ip_output


class TLS_Scanner:
    """
    TLS-Scanner wrapper module.
    """

    __cache = {}
    __ip_cache = {}

    def __init__(self):
        """
        Loads TLS-Scanner variables.
        """
        self.__tls_scanner = f"dependencies{sep}TLS-Scanner{sep}apps{sep}TLS-Server-Scanner.jar"
        self.__input_dict = {}

    def input(self, **kwargs):
        """
        Set the input for the modules
        :param kwargs: See below

        :Keyword Arguments:
        * *hostname* (``str``) --
          The hostname of the website to analyze. Can be an IP or a Name (DNS)
        * *args* (``list of str``) --
          Raw arguments for TLS-Scanner executable
        * *force* (``bool``) --
          Force rescan by ignoring cached results , Default *False*
        * *clean* (``bool``) --
          clear the cache, default *False*
        """
        self.__input_dict = kwargs

    def output(self, **kwargs) -> dict:
        """
        Output method of module
        :param kwargs: See below

        :Keyword Arguments:
        * *hostname* (``str``) --
          The hostname of the website analyzed. Can be an IP or a Name (DNS).

        :return: Empty dict if not found, results dict if found.
        :rtype: dict
        :raise AssertionError: If hostname parameter is not found.
        """
        '''
        if "hostname" in kwargs:
            kwargs["hostname"] = link_sep(kwargs["hostname"])[0]
        '''
        if "hostname" not in kwargs:
            raise AssertionError("Missing parameter hostname.")
        elif kwargs["hostname"] not in self.__cache:
            return {}  # not found
        else:
            return self.__cache

    def __merge(self, x, y) -> dict:
        """
        Internal module, merge two dicts
        :param x: source dict
        :type x: dict
        :param y: destination dict
        :type y: dict
        :return: merged dict
        :rtype: dict
        """
        z = x.copy()
        z.update(y)
        return z

    def __clean_cache(self) -> bool:
        """
        Clear the cache
        :return: True
        :rtype: bool
        """
        self.__cache = {}
        self.__ip_cache = {}
        return True

    def __update_cache(self, cache, ip_cache):
        """
        Update the cache
        :param cache: new results to add to the cache
        :param ip_cache: new results of the reverse cache
        """
        for site in cache:
            if site not in self.__cache:
                self.__cache[site] = cache[
                    site
                ]  # for each site, update the cache if not in it
            else:
                for ip in cache[site]:
                    self.__cache[site][ip] = self.__merge(
                        self.__cache[site][ip], cache[site][ip]
                    )  # if present, merge
        self.__ip_cache.update(ip_cache)

    def run(self, **kwargs) -> dict:
        """

        Set the input for the modules, processes the request and returns output.
        :param kwargs: See below

        :Keyword Arguments:
        * *hostname* (``str``) --
          The hostname of the website to analyze. Can be an IP or a Name (DNS)
        * *args* (``list of str``) --
          Raw arguments for TLS-Scanner executable
        * *force* (``bool``) --
          Force rescan by ignoring cached results , Default *False*
        * *clean* (``bool``) --
          clear the cache, default *False*

        :return: Parsed results.
        :rtype: dict
        :raise AssertionError: If hostname parameter is not found.
        """
        self.input(**kwargs)
        if "hostname" not in self.__input_dict:
            raise AssertionError("IP or hostname args not found.")
        else:  # initialization of parameters
            self.__input_dict["hostname"] = url_strip(
                self.__input_dict["hostname"], strip_www=True
            )
            args = self.__input_dict["args"] if "args" in self.__input_dict else [
            ]
            force = (
                self.__input_dict["force"] if "force" in self.__input_dict else False
            )
            clean = (
                self.__input_dict["clean"] if "clean" in self.__input_dict else False
            )
            Validator(
                [
                    (self.__input_dict["hostname"], str),
                    (args, list),
                    (force, bool),
                    (clean, bool),
                ]
            )
            self.__scan(
                str(self.__input_dict["hostname"]),
                args=args,
                force=force,
                clean=clean,
            )
        return self.output(hostname=self.__input_dict["hostname"])

    def __scan(self, hostname: str, args: [str], force: bool, clean: bool):
        """
        Scan internal module
        :param hostname: Hostname or IP
        :type hostname: str
        :param args: Raw args for TLS-Scanner
        :type args: list of str
        :param force: Force the rescan, ignore the cached result.
        :type force: bool
        :param clean: Clear the cache.
        :type clean: bool

        """
        if clean:
            self.__clean_cache()
        self.__scan_hostname(hostname, args, force)

    def __scan_hostname(self, hostname: str, args: [str], force: bool):
        """
        Internal module of scan
        :param hostname: Hostname or IP
        :type hostname: str
        :param args: Raw args for TLS-Scanner
        :type args: list of str
        :param force: Force the rescan, ignore the cached result.
        """
        if force:
            logging.debug("Starting TLS-Scanner analysis")
            with open(devnull, "w") as null:
                cmd = [
                    "java",
                    "-jar",
                    self.__tls_scanner,
                    "-connect",
                    f"{hostname}",
                    "-scanDetail",
                    "QUICK",
                    "-server_name",
                    f"{hostname.split(':')[0]}",
                ]

                if args:
                    logging.debug(f"Scanning with personalized args: {args}")
                    cmd.append("-vulns")
                    cmd.append(",".join(args))

                output = ""
                try:
                    output = subprocess.check_output(
                        cmd,
                        stderr=sys.stderr,
                        # check=True,  # check call equivalent
                        text=True,  # text as an input
                    )
                    if logging.getLogger().isEnabledFor(logging.DEBUG):
                        print(output)

                except subprocess.CalledProcessError as c:
                    logging.debug(c)

                cache, ip_cache = Parser(output).output()
                self.__update_cache(cache, ip_cache)

        else:
            if hostname not in self.__cache:
                self.__scan_hostname(
                    hostname, args=args, force=True
                )  # with force = True
