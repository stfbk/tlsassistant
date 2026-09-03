import requests
from utils.urls import url_strip
from utils.validation import Validator


class Parser:
    """
    Parser for the ctlogs.dev API
    """

    def __init__(self, results):
        """
        :param results: The results from the ctlogs.dev API
        :type results: list
        """
        self.__cache = {}
        self.__parse(results)

    def __parse(self, results):
        """
        Parses the results from the ctlogs.dev API
        :param results: The results from the ctlogs.dev API
        :type results: list
        """
        for result in results:
            for cert in result["rows"]:
                url = cert["match"]
                cert.pop("match", None)
                if url not in self.__cache:
                    self.__cache[url] = [cert]
                else:
                    self.__cache[url].append(cert)

    def output(self):
        """
        Returns the cached results
        :return: The output of the ctlogs.dev API
        """
        return self.__cache


class Certificate:
    """
    Calls the ctlogs.dev API and returns the results
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
        Runs the ctlogs.dev API

        :param kwargs: The input arguments
        :type kwargs: dict

        :Keyword Arguments:
            * *hostname* (``str``) -- The hostname to lookup
            * *force* (``bool``) -- Force the lookup
            * *expired* (``bool``) -- Include or exclude expired certificates, default is False (excluded)

        :return: The cached results
        :rtype: dict
        """
        self.input(**kwargs)
        if "hostname" not in self.__input_dict:
            raise AssertionError("IP or hostname args not found.")
        force = self.__input_dict["force"] if "force" in self.__input_dict else False
        expired = (
            self.__input_dict["expired"] if "expired" in self.__input_dict else False
        )
        Validator(
            [(self.__input_dict["hostname"], str), (force, bool), (expired, bool)]
        )

        self.__input_dict["hostname"] = url_strip(
            self.__input_dict["hostname"], strip_www=True
        )
        self.__worker(self.__input_dict["hostname"], force, expired)
        return self.output(hostname=self.__input_dict["hostname"])

    def __worker(self, url: str, force: bool, expired: bool):
        """
        The worker method that does the actual work

        :param url: The hostname to lookup
        :type url: str
        :param force: Force the lookup and ignore cached results
        :type force: bool
        """
        if force:
            self.__cache[url] = Parser(self.__requester(url, expired=expired)).output()

        else:
            if url not in self.__cache:
                self.__worker(url, force=True, expired=expired)

    def __requester(self, url, expired=True) -> dict:
        """
        Requests the ctlogs.dev API

        :param url: The hostname to lookup
        :type url: str
        :return: The results of the ctlogs.dev API
        :rtype: List[dict]
        :raise Exception: If the hostname is not found or could not return any results
        """
        has_next = True
        final_req = {}
        results = []
        request_url = f"https://ctlogs.dev/search?q=.{url}&output=json{'&exclude=expired' if not expired else ''}"
        while has_next:
            req = requests.get(
                request_url,
                timeout=30
            )

            if not req.ok or req.status_code != 200:
                raise Exception("Couldn't retrieve any result.")

            req = req.json()
            has_next = req.get("has_next", None)
            next_cursor = req.get("next_cursor", None)
            request_url = f"https://ctlogs.dev/search?q=.{url}&output=json{'&exclude=expired' if not expired else ''}&after={next_cursor}"
            if req:
                results.append(req)

        return results            
