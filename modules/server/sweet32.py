from modules.configuration.configuration_base import Config_base
from modules.server.testssl_base import Testssl_base
from utils.validation import Validator


class Sweet32(Testssl_base):
    class Parse_configuration(Config_base):

        def fix(self, vhost):
            key = 'SSLCipherSuite'
            if key not in vhost:
                vhost[key] = ""
            vhost[key] = f"{vhost[key]}{':' if vhost[key] else ''}!3DES"

        def condition(self, vhost, openssl: str = None, ignore_openssl=False):
            key = 'SSLCipherSuite'
            openssl_greater_than = '1.1.0'

            if openssl is None:
                openssl = ""
            Validator([(openssl, str)])
            if key not in vhost:
                vhost[key] = ""
            if not ignore_openssl:
                if openssl:
                    is_safe = self.openSSL.is_safe(ver1=openssl_greater_than, ver2=openssl)
                else:
                    is_safe = self.openSSL.is_safe(ver1=openssl_greater_than)
                return not is_safe and "!3des" not in vhost[key].lower()  # is vulnerable if True
            else:
                return "!3des" not in vhost[key].lower()  # is vulnerable if True

    conf = Parse_configuration()

    # to override
    def _set_arguments(self):
        self._arguments = ["-W"]

    # to override
    def _worker(self, results):
        return self._obtain_results(results, ["SWEET32"])
