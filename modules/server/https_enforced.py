from modules.configuration.configuration_base import Parse_configuration_checks_redirect
from modules.server.hsts_base import Hsts_base
from utils.logger import Logger


class Https_enforced(Hsts_base):
    conf = Parse_configuration_checks_redirect()

    def _get_logger(self):
        return Logger("Https Not Enforced")

    # to override
    def _set_arguments(self):
        self._arguments = self._instance.HTTPS

    # to override
    def _worker(self, results):
        return self._obtain_results(results)
