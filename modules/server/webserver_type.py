from utils import logger

import requests
class WebserverType:
    _output = {}
    def __init__(self):
        self.__input = {}
        self.__logging = logger.Logger("WebserverType")

    def input(self, **kwargs):
        self.__input = kwargs

    def run(self, **kwargs):
        self.input(**kwargs)
        self._worker()
        return self.output()

    def _worker(self):
        for host in self.__input.get("hosts", []):
            webserver = "http://"+host if not host.startswith("http") else host
            try:
                res = requests.get(webserver, headers={"User-Agent": "Mozilla/5.0"})
            except Exception as e:
                self.__logging.debug(e.__str__())
                self.__logging.warning(f"Error occurred while connecting to {host}")
                continue
            server_type = res.headers.get("Server", "")
            if server_type:
                self._output[host] = server_type

    def output(self):
        return self._output.copy()