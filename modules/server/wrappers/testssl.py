import json
import subprocess
import sys
from os import sep, devnull, path, remove
import uuid
import logging
from utils.validation import Validator
from utils.urls import url_strip, link_sep, validate_ip


class Parser:
    """
    Class used to parse testssl results.
    The results are parsed and grouped by IP/SITE.
    """

    def __init__(self, to_parse: dict):
        """
        Init method.
        :param to_parse: Raw JSON output of testssl.sh, given as a python dict.
        :type to_parse: dict
        """
        self.__results = to_parse
        self.__output = {}
        self.__ip_output = {}
        self.__parse()

    def __parse(self):  # parse method
        for result in self.__results:  # for each result
            site, ip = result["ip"].rsplit("/", 1)  # split ip, it usually is website/ip
            site = ip if site == "" else site  # if site is empty, we use the ip
            if ip != "":  # if the ip is missing, it's nothing we care about.
                if (
                    site not in self.__output
                ):  # if site is not in output, it's the first time that we see it.
                    self.__output[site] = {}  # site inizialization
                if (
                    ip not in self.__output[site]
                ):  # same for the previous comment, but with the IP
                    self.__output[site][ip] = {}  # ip inizialization
                self.__ip_output[ip] = site  # reverse cache
                id = result["id"]  # obtain ID
                result.pop("id", None)  # Remove ID from results
                result.pop("ip", None)  # Remove IP from results
                self.__output[site][ip][id] = result  # put the result

    def output(self) -> (dict, dict):
        """
        Output.
        :return: returns parsed cache dicts.
        :rtype: tuple of dict
        """
        return self.__output, self.__ip_output


class Testssl:
    """
    Testssl wrapper module.
    """

    __cache = {}
    __ip_cache = {}

    def __init__(self):
        """
        Loads testssl variables.
        """
        self.__testssl = f"dependencies{sep}testssl.sh{sep}testssl.sh"
        self.__input_dict = {}

    def input(self, **kwargs):
        """
        Set the input for the modules
        :param kwargs: See below

        :Keyword Arguments:
        * *hostname* (``str``) --
          The hostname of the website to analyze. Can be an IP or a Name (DNS)
        * *args* (``list of str``) --
          Raw arguments for testssl.sh executable
        * *force* (``bool``) --
          Force rescan by ignoring cached results , Default *False*
        * *one* (``bool``) --
          Add ``--IP=one`` to testssl.sh executable calls, default *True*
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
        if "hostname" in kwargs:
            kwargs["hostname"] = link_sep(kwargs["hostname"])[0]

        if "hostname" not in kwargs:
            raise AssertionError("Missing parameter hostname.")
        elif kwargs["hostname"] not in self.__cache:
            return {}  # not found
        else:
            return (
                self.__cache[kwargs["hostname"]]  # return cache value if
                if not validate_ip(kwargs["hostname"])  # it's not an IP
                else {  # else return the IP value
                    kwargs["hostname"]: self.__cache[
                        self.__ip_cache[kwargs["hostname"]]
                    ][kwargs["hostname"]]
                }
            )

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
          Raw arguments for testssl.sh executable
        * *force* (``bool``) --
          Force rescan by ignoring cached results , Default *False*
        * *one* (``bool``) --
          Add ``--IP=one`` to testssl.sh executable calls, default *True*
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
            args = self.__input_dict["args"] if "args" in self.__input_dict else []
            force = (
                self.__input_dict["force"] if "force" in self.__input_dict else False
            )
            one = self.__input_dict["one"] if "one" in self.__input_dict else True
            clean = (
                self.__input_dict["clean"] if "clean" in self.__input_dict else False
            )
            Validator(
                [
                    (self.__input_dict["hostname"], str),
                    (args, list),
                    (force, bool),
                    (one, bool),
                    (clean, bool),
                ]
            )
            self.__scan(
                str(self.__input_dict["hostname"]),
                args=args,
                force=force,
                one=one,
                clean=clean,
            )
        return self.output(hostname=self.__input_dict["hostname"])

    def __scan(self, hostname: str, args: [str], force: bool, one: bool, clean: bool):
        """
        Scan internal module
        :param hostname: Hostname or IP
        :type hostname: str
        :param args: Raw args for testssl.sh
        :type args: list of str
        :param force: Force the rescan, ignore the cached result.
        :type force: bool
        :param one: Add '--IP=one' to testssl.sh calls.
        :type one: bool
        :param clean: Clear the cache.
        :type clean: bool

        """
        if clean:
            self.__clean_cache()
        self.__scan_hostname(hostname, args, force, one)

    def __scan_hostname(self, hostname: str, args: [str], force: bool, one: bool):
        """
        Internal module of scan
        :param hostname: Hostname or IP
        :type hostname: str
        :param args: Raw args for testssl.sh
        :type args: list of str
        :param force: Force the rescan, ignore the cached result.
        :type force: bool
        :param one: Add '--IP=one' to testssl.sh calls.
        :type one: bool
        """
        if force:
            logging.debug("Starting testssl analysis")
            file_name = uuid.uuid4().hex
            logging.debug(
                f"Scanning {hostname}, saving result to temp file {file_name}"
            )
            with open(devnull, "w") as null:
                cmd = [
                    "bash",
                    self.__testssl,
                    f"--jsonfile=dependencies{sep}{file_name}.json",
                ]
                if one and not validate_ip(hostname):
                    logging.debug("Scanning with --IP=one..")
                    cmd.append(f"--ip=one")
                if args:
                    logging.debug(f"Scanning with personalized args: {args}")
                    for arg in args:
                        cmd.append(arg)
                cmd.append(hostname)
                try:
                    subprocess.run(
                        cmd,
                        stderr=sys.stderr,
                        stdout=(
                            sys.stdout
                            if logging.getLogger().isEnabledFor(
                                logging.DEBUG
                            )  # if the user asked for debug mode, let him see the output.
                            else null  # else /dev/null
                        ),
                        check=True,  # check call equivalent
                        text=True,  # text as an input
                        input="yes",  # if asked, write 'yes' on each prompt
                    )
                except subprocess.CalledProcessError as c:
                    logging.debug(c)
                if path.exists(
                    f"dependencies{sep}{file_name}.json"
                ):  # load the temp file results
                    with open(
                        f"dependencies{sep}{file_name}.json", "r"
                    ) as file:  # load temp file
                        data = file.read()
                        cache, ip_cache = Parser(json.loads(data)).output()
                        self.__update_cache(cache, ip_cache)
                    remove(f"dependencies{sep}{file_name}.json")
        else:
            if not validate_ip(
                hostname
            ):  # recursive: if force : false, check if in cache. if not, recursive call
                if link_sep(hostname)[0] not in self.__cache:
                    self.__scan_hostname(
                        hostname, args=args, force=True, one=one
                    )  # with force = True
            else:
                if (
                    link_sep(hostname)[0] not in self.__ip_cache
                ):  # if it's an ip, check for it in reverse proxy
                    self.__scan_hostname(hostname, args=args, force=True, one=one)
