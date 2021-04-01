import json
import subprocess
import sys
from os import sep, devnull, path, remove
import uuid
import logging


class Parser:
    def __init__(self, to_parse):
        self.__results = to_parse
        self.__output = {}
        self.__ip_output = {}
        self.__parse()

    def __parse(self):
        for result in self.__results:
            site, ip = result["ip"].rsplit("/", 1)
            if site == "" or validate_ip(site):
                site = "IP_SCANS"
            if ip != "":
                if site not in self.__output:
                    self.__output[site] = {}
                if ip not in self.__output[site]:
                    self.__output[site][ip] = []
                self.__ip_output[ip] = site
                self.__output[site][ip].append(result)

    def output(self) -> (dict, dict):
        return self.__output, self.__ip_output


def validate_ip(ip: str) -> bool:
    a = ip.split(".")
    if len(a) != 4:
        return False
    for x in a:
        if not x.isdigit():
            return False
        i = int(x)
        if i < 0 or i > 255:
            return False
    return True


class Testssl:
    __cache = {}
    __ip_cache = {}

    def __init__(self):
        self.__testssl = f"dependencies{sep}3.0.4{sep}testssl.sh-3.0.4{sep}testssl.sh"
        self.__input_dict = {}

    def input(self, **kwargs):
        self.__input_dict = kwargs

    def output(self, **kwargs) -> dict:
        return (
            self.__cache[kwargs["hostname"]]
            if not validate_ip(kwargs["hostname"])
            else {
                kwargs["hostname"]: self.__cache[self.__ip_cache[kwargs["hostname"]]][
                    kwargs["hostname"]
                ]
            }
        )

    def __merge(self, x, y):
        z = x.copy()
        z.update(y)
        return z

    def __clean_cache(self) -> bool:
        self.__cache = {}
        self.__ip_cache = {}
        return True

    def __update_cache(self, cache, ip_cache):
        for site in cache:
            if site not in self.__cache:
                self.__cache[site] = {}
            self.__cache[site] = self.__merge(self.__cache[site], cache[site])

        self.__ip_cache = self.__merge(self.__ip_cache, ip_cache)

    def run(self, **kwargs) -> dict:
        self.input(**kwargs)
        if "hostname" not in self.__input_dict:
            raise AssertionError("IP or hostname args not found.")
        else:
            self.__scan(
                str(self.__input_dict["hostname"]),
                args=self.__input_dict["args"] if "args" in self.__input_dict else None,
                force=self.__input_dict["force"]
                if "force" in self.__input_dict
                else False,
                one=self.__input_dict["one"] if "one" in self.__input_dict else True,
                clean=self.__input_dict["clean"]
                if "clean" in self.__input_dict
                else False,
            )
        return self.output(hostname=self.__input_dict["hostname"])

    def __scan(self, hostname: str, args: [str], force: bool, one: bool, clean: bool):
        if clean:
            self.__clean_cache()
        self.__scan_hostname(hostname, args, force, one)

    def __scan_hostname(self, hostname: str, args: [str], force: bool, one: bool):
        # scan
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
                    check=True,
                    text=True,
                    input="yes",
                )
                if path.exists(f"dependencies{sep}{file_name}.json"):
                    with open(
                        f"dependencies{sep}{file_name}.json", "r"
                    ) as file:  # load temp file
                        data = file.read()
                        cache, ip_cache = Parser(json.loads(data)).output()
                        self.__update_cache(cache, ip_cache)
                    remove(f"dependencies{sep}{file_name}.json")
        else:
            if not validate_ip(hostname):
                if hostname not in self.__cache:
                    self.__scan_hostname(hostname, args=args, force=True, one=one)
            else:
                if hostname not in self.__ip_cache:
                    print(self.__ip_cache)
                    self.__scan_hostname(hostname, args=args, force=True, one=one)
