import logging

from utils.validation import Validator
from utils.urls import url_domain, port_parse
import requests
import os.path
from os import sep
from base64 import b64decode
from json import loads


class Parse:
    __path_moz = f"dependencies{sep}nsSTSPreloadList.inc"
    __path_gog = f"dependencies{sep}transport_security_state_static.json"

    def __init__(self, moz=True):
        self.__cache = {}
        if moz:
            self.__parse_moz(self.__path_moz)
        else:
            self.__parse_gog(self.__path_gog)

    def __parse_moz(self, path):
        if os.path.exists(path):
            with open(path, "r") as file:
                start_parsing = False
                for line in file:
                    if "%%" in line:  # start n stop
                        start_parsing = True if not start_parsing else False
                    if start_parsing and "%%" not in line:
                        if len(line.replace("\n", "").split(",")) == 2:
                            host, no = line.replace("\n", "").split(",")
                            self.__cache[host] = no

        else:
            raise FileNotFoundError("The file provided for mozilla HSTS doesn't exist.")

    def __parse_gog(self, path):
        if os.path.exists(path):
            with open(path, "r") as file:
                raw_results = b64decode(file.read()).decode().split("\n")
                gog = loads(
                    "\n".join(
                        [
                            line
                            for line in raw_results
                            if not line.lstrip().startswith("//")
                        ]
                    )
                )
            for sub in gog["entries"]:
                name = sub["name"]
                sub.pop("name", None)
                self.__cache[name] = sub
        else:
            raise FileNotFoundError("The file provided for google HSTS doesn't exist.")

    def output(self):
        return self.__cache


class Https:
    HTTPS = 0
    HSTSSET = 1
    HSTSPRELOAD = 2
    SERVERINFO = 3
    __cache = {}
    __preloaded_moz = {}
    __preloaded_gog = {}
    __output = {}
    __headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/39.0.2171.95 "
        "Safari/537.36"
    }

    def __init__(self):
        self.__input_dict = {}

    def input(self, **kwargs):
        self.__input_dict = kwargs

    def output(self, **kwargs):
        return (
            self.__output[kwargs["hostname"]]
            if "hostname" in kwargs and kwargs["hostname"] in self.__cache
            else False
        )

    def run(self, **kwargs):
        self.input(**kwargs)
        if "hostname" not in self.__input_dict:
            raise AssertionError("IP or hostname args not found.")
        elif "type" not in self.__input_dict:
            raise AssertionError("Type args not found.")
        else:  # initialization of parameters
            self.__input_dict["hostname"] = url_domain(self.__input_dict["hostname"])
            force = (
                self.__input_dict["force"] if "force" in self.__input_dict else False
            )
            if "port" not in self.__input_dict:
                self.__input_dict["port"] = "443"
            port_to_add = (
                ":" + port_parse(self.__input_dict["port"])
                if self.__input_dict[  # self.__input_dict["type"] != self.HTTPS and
                    "port"
                ]
                != "443"
                else ""
            )
            Validator(
                [
                    (self.__input_dict["hostname"], str),
                    (force, bool),
                    (self.__input_dict["type"], int),
                ]
            )
            # request
            link = (
                f'{"http" if self.__input_dict["type"] == self.HTTPS else "https"}://'
                f'{self.__input_dict["hostname"]}'
                f"{port_to_add}"
            )
            self.__output[link] = self.__worker(
                link,
                self.__input_dict["type"],
                force,
            )

        return self.output(hostname=link)

    def __chose_results(self, type: int, response: requests.Response):
        logging.debug(response.headers)
        if type == self.HTTPS:
            return (
                response.is_redirect or response.is_permanent_redirect
            ) and response.headers["location"].startswith("https")
        elif type == self.SERVERINFO:
            return response.headers["server"] if "server" in response.headers else ""
        elif type == self.HSTSSET:
            return "strict-transport-security" in response.headers
        else:
            if not self.__preloaded_moz:
                logging.debug("Preloading mozilla hsts..")
                self.__preloaded_moz = Parse().output()
            if not self.__preloaded_gog:
                logging.debug("Preloading google hsts..")
                self.__preloaded_gog = Parse(moz=False).output()
            if response.request:
                parsed_url = url_domain(response.request.url)
                logging.debug(f"url : {parsed_url} parsed")
            else:
                parsed_url = None
            return (
                parsed_url in self.__preloaded_moz or parsed_url in self.__preloaded_gog
            )

    def __worker(self, link: str, type: int, force: bool):

        if force:
            try:

                self.__cache[link] = requests.head(
                    link, headers=self.__headers, timeout=5
                )
            except requests.exceptions.SSLError as ex:
                logging.error(f"I can't connect to SSL/TLS:\n{ex}")
                logging.warning(
                    "The HTTPS_HSTS analysis cannot proceed and result will be set as vulnerable."
                )
                return self.__chose_results(
                    type, requests.Response()
                )  # default response
            except requests.exceptions.ConnectTimeout as ex:
                logging.error(f"I can't connect to host:\n{ex}")
                logging.warning(
                    "The HTTPS_HSTS analysis cannot proceed and result will be set as vulnerable."
                )
                return self.__chose_results(
                    type, requests.Response()
                )  # default response
        else:
            if link not in self.__cache:
                self.__worker(link, type, force=True)
        response = self.__cache[link]
        if response.ok:
            print(self.__cache)
            return self.__chose_results(type, response)
        else:
            raise Exception(f"Received Status Code {response.status_code}, abort.")
