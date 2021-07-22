import requests
from utils.urls import url_strip
from utils.validation import Validator


class Parser:
    """
    Parser for the crt.sh API
    """

    __cache = {}

    def __init__(self, results):
        """
        :param results: The results from the crt.sh API
        :type results: list
        """
        self.__parse(results)

    def __parse(self, results):
        """
        Parses the results from the crt.sh API
        :param results: The results from the crt.sh API
        :type results: list
        """
        for cert in results:
            url = cert["common_name"]
            cert.pop("common_name", None)
            if url not in self.__cache:
                self.__cache[url] = [cert]
            else:
                self.__cache[url].append(cert)

    def output(self):
        """
        Returns the cached results
        :return: The output of the crt.sh API
        """
        return self.__cache


class Certificate:
    """
    Calls the crt.sh API and returns the results
    """

    __cache = {}

    def __init__(self):
        self.__input_dict = {}

    def input(self, **kwargs):
        """
        Sets the input arguments

        :param kwargs: The input arguments
        :type kwargs: dict

        :Keyword Arguments:
            * *hostname* (``str``) -- The hostname to lookup
            * *force* (``bool``) -- Force the lookup
        """
        self.__input_dict = kwargs

    def output(self, **kwargs) -> dict:
        """
        Returns the cached results

        :param kwargs: The input arguments
        :type kwargs: dict

        :Keyword Arguments:
            * *hostname* (``str``) -- The hostname to lookup

        :return: The cached results
        :rtype: dict
        """
        return (
            self.__cache[kwargs["hostname"]]
            if "hostname" in kwargs and kwargs["hostname"] in self.__cache
            else {}
        )

    def run(self, **kwargs):
        """
        Runs the crt.sh API

        :param kwargs: The input arguments
        :type kwargs: dict

        :Keyword Arguments:
            * *hostname* (``str``) -- The hostname to lookup
            * *force* (``bool``) -- Force the lookup

        :return: The cached results
        :rtype: dict
        """
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
        """
        The worker method that does the actual work

        :param url: The hostname to lookup
        :type url: str
        :param force: Force the lookup and ignore cached results
        :type force: bool
        """
        if force:
            self.__cache[url] = Parser(self.__requester(url)).output()
        else:
            if url not in self.__cache:
                self.__worker(url, force=True)

    def __requester(self, url) -> dict:
        """
        Requests the crt.sh API

        :param url: The hostname to lookup
        :type url: str
        :return: The results of the crt.sh API
        :rtype: dict
        :raise Exception: If the hostname is not found or could not return any results
        """
        req = requests.get(f"https://crt.sh/?q=%.{url}&output=json")

        if not req.ok or req.status_code != 200:
            raise Exception("Couldn't retrieve any result.")

        return req.json()
