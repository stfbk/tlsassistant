from modules.configuration.configuration_base import Parse_configuration_strict_security
from modules.server.hsts_base import Hsts_base
from utils.logger import Logger


class Hsts_set(Hsts_base):
    conf = (
        Parse_configuration_strict_security()
    )  # TODO: Check for port 443 or apply it everywhere?

    def _get_logger(self):
        return Logger("Hsts Not Set")

    # to override
    def _set_arguments(self):
        self._arguments = self._instance.HSTSSET

    # to override
    def _worker(self, results):
        return self._obtain_results(results)
