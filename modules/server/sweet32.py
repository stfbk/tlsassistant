from modules.configuration.configuration_base import Parse_configuration_ciphers
from modules.server.testssl_base import Testssl_base


class Sweet32(Testssl_base):
    conf = Parse_configuration_ciphers(openssl="1.1.0", ciphers=["3DES"])

    # to override
    def _set_arguments(self):
        self._arguments = ["-W"]

    # to override
    def _worker(self, results):
        return self._obtain_results(results, ["SWEET32"])
