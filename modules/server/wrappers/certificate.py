import requests
from utils.urls import url_strip
from utils.validation import Validator


class Parser:
    __cache = {}

    def __init__(self, results):
        self.__parse(results)

    def __parse(self, results):
        for cert in results:
            url = cert["common_name"]
            cert.pop("common_name", None)
            if url not in self.__cache:
                self.__cache[url] = [cert]
            else:
                self.__cache[url].append(cert)

    def output(self):
        return self.__cache


class Certificate:
    __cache = {}

    def __init__(self):
        self.__input_dict = {}

    def input(self, **kwargs):
        self.__input_dict = kwargs

    def output(self, **kwargs) -> dict:
        return (
            self.__cache[kwargs["hostname"]]
            if "hostname" in kwargs and kwargs["hostname"] in self.__cache
            else {}
        )

    def run(self, **kwargs):
        self.input(**kwargs)
        if "hostname" not in self.__input_dict:
            raise AssertionError("IP or hostname args not found.")
        force = self.__input_dict["force"] if "force" in self.__input_dict else False
        Validator([(self.__input_dict["hostname"], str), (force, bool)])

        self.__input_dict["hostname"] = url_strip(
            self.__input_dict["hostname"], strip_www=True
        )
        self.__worker(self.__input_dict["hostname"], force)
        return self.output(hostname=self.__input_dict["hostname"])

    def __worker(self, url: str, force: bool):
        if force:
            self.__cache[url] = Parser(self.__requester(url)).output()
        else:
            if url not in self.__cache:
                self.__worker(url, force=True)

    def __requester(self, url) -> dict:
        req = requests.get(f"https://crt.sh/?q=%.{url}&output=json")

        if not req.ok or req.status_code != 200:
            raise Exception("Couldn't retrieve any result.")

        return req.json()
