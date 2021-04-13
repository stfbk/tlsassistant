from utils.validation import Validator
from utils.urls import url_strip
import requests


class Https:
    HTTPS = 0
    HSTSSET = 1
    # HSTSPRELOAD = 2
    SERVERINFO = 3
    __cache = {}
    __output = {}
    __headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) '
                      'Chrome/39.0.2171.95 '
                      'Safari/537.36'}

    def __init__(self):
        self.__input_dict = {}

    def input(self, **kwargs):
        self.__input_dict = kwargs

    def output(self, **kwargs):
        return (
            self.__output[kwargs["hostname"]]
            if "hostname" in kwargs and kwargs["hostname"] in self.__cache
            else None
        )

    def run(self, **kwargs):
        self.input(**kwargs)
        if "hostname" not in self.__input_dict:
            raise AssertionError("IP or hostname args not found.")
        elif "type" not in self.__input_dict:
            raise AssertionError("Type args not found.")
        else:  # initialization of parameters
            self.__input_dict["hostname"] = url_strip(self.__input_dict["hostname"], strip_www=True)
            force = (
                self.__input_dict["force"] if "force" in self.__input_dict else False
            )
            Validator(
                [
                    (self.__input_dict["hostname"], str),
                    (force, bool),
                    (self.__input_dict["type"], int),
                ]
            )

            # request
            link = f'{"http" if self.__input_dict["type"] == self.HTTPS else "https"}://{self.__input_dict["hostname"]}'
            self.__output[link] = self.__worker(
                link, self.__input_dict["type"], force
            )

        return self.output(hostname=link)

    def chose_results(self, type: int, response: requests.Response):
        if type == self.HTTPS:
            return response.headers["location"].startswith("https") and (
                    response.status_code == 301 or response.status_code == 302
            )
        elif type == self.SERVERINFO:
            return response.headers["server"] if "server" in response.headers else ""
        elif type == self.HSTSSET:
            return "strict-transport-security" in response.headers
        else:
            pass  # todo implement self.HSTSPRELOAD

    def __worker(self, link: str, type: int, force: bool):

        if force:
            self.__cache[link] = requests.head(link, headers=self.__headers, timeout=60)
        else:
            if link not in self.__cache:
                self.__worker(link, type, force=True)
        response = self.__cache[link]
        if response.ok:
            return self.chose_results(type, response)
        else:
            raise Exception(f"Received Status Code {response.status_code}, abort.")
