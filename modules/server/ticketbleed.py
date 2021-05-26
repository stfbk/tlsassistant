from modules.server.testssl_base import Testssl_base
import logging


class Ticketbleed(Testssl_base):

    # to override
    def _set_arguments(self):
        self._arguments = ["-T"]

    # to override
    def _worker(self, results):
        return self._obtain_results(results, ["ticketbleed"])
