import json
import subprocess
import sys
from os import sep, devnull, path, remove
import uuid
import logging


class Testssl:
    def __init__(self):
        self.__input_dict = {}
        self.__scan_dict = {}
        self.__output_dict = {}

    def input(self, **kwargs):
        self.__input_dict = kwargs

    def output(self, type=None) -> dict:
        return self.__output_dict

    def run(self, **kwargs):
        self.input(**kwargs)
        if "force" not in self.__input_dict:
            self.__input_dict["force"] = False
        if "ip" not in self.__input_dict or "hostname" not in self.__input_dict:
            raise AssertionError("IP or hostname args not found.")
        elif "hostname" in self.__input_dict:
            self.__scan(str(self.__input_dict["hostname"]), self.__input_dict["force"])
        else:
            self.__scan_ip(self.__input_dict["ip"], self.__input_dict["force"])
        return self.output()

    def __scan_hostname(self, hostname: str) -> [str]:  # todo: implement
        return []

    def __scan(self, hostname: str, force=False) -> [dict]:
        return [self.__scan_ip(ip, force) for ip in self.__scan_hostname(hostname)]

    def __scan_ip(self, ip: str, force: bool) -> dict:
        # scan
        if force:
            file_name = uuid.uuid4().hex
            logging.debug(f"Scanning {ip}, saving result to temp file {file_name}")
            with open(devnull, "w") as null:
                subprocess.check_call(
                    [
                        "bash",
                        "testssl.sh",
                        f"{ip}",
                        "--jsonfile",
                        f"dependencies{sep}{file_name}.json",
                    ],
                    stderr=sys.stderr,
                    stdout=(
                        sys.stdout
                        if logging.getLogger().isEnabledFor(
                            logging.DEBUG
                        )  # if the user asked for debug mode, let him see the output.
                        else null  # else /dev/null
                    ),
                )
                if path.exists(f"dependencies{sep}{file_name}.json"):
                    with open(
                        f"dependencies{sep}{file_name}.json", "r"
                    ) as file:  # load temp file
                        data = file.read()
                        self.__scan_dict[ip] = json.loads(data)
                    remove(f"dependencies{sep}{file_name}.json")
        else:
            if ip not in self.__scan_dict:
                self.__scan_dict = self.__scan(ip, force=True)
        return self.__scan_dict[ip]
