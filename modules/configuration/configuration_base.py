from ssl import OPENSSL_VERSION

from utils.validation import Validator


class OpenSSL:
    VERSION = OPENSSL_VERSION.split()[1]

    def less_than(self, ver1, ver2=VERSION):
        return self.__compare(ver1, ver2)

    def greater_than(self, ver1, ver2=VERSION):
        return self.__compare(ver1, ver2, reverse=True)

    def is_safe(self, ver1, ver2=VERSION):
        return self.less_than(ver1, ver2)

    def __compare(self, ver1, ver2, reverse=False):
        assert (
            len(ver1) == 6 or len(ver1) == 5
        ), "OpenSSL version must be 5 or 6 char long.\nFor example '1.1.1f'\nFor version 3.0 use 3.0.0."
        assert (
            len(ver2) == 6 or len(ver2) == 5
        ), "OpenSSL version must be 5 or 6 char long.\nFor example '1.1.1f''\nFor version 3.0 use 3.0.0."
        # even the versions
        if len(ver1) == 6 and len(ver2) == 5:
            ver1 = ver1[:-1]
        elif len(ver2) == 6 and len(ver1) == 5:
            ver2 = ver2[:-1]
        return (ver1 < ver2) if not reverse else (ver1 > ver2)


class Config_base:
    openSSL = OpenSSL()

    def condition(self, vhost):
        raise NotImplementedError

    def fix(self, vhost):
        raise NotImplementedError

    def is_empty(self, vhost):
        raise NotImplementedError


class Parse_configuration_protocols(Config_base):
    def is_empty(self, vhost):
        return self.__key not in vhost or not vhost[self.__key]

    def __init__(self, openssl: str, protocols: dict):
        self.__openssl = openssl
        self.__protocols = protocols
        self.__key = "SSLProtocol"
        Validator([(openssl, str), (protocols, dict)])

    def fix(self, vhost):
        key = self.__key
        v = Validator()
        if key not in vhost:
            vhost[key] = "ALL"
        for cipher, operation in self.__protocols.items():
            v.string(cipher)
            vhost[key] = f"{vhost[key]}{' ' if vhost[key] else ''}{operation}{cipher}"

    def condition(self, vhost, openssl: str = None, ignore_openssl=False):
        key = self.__key
        openssl_greater_than = self.__openssl
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

            return not is_safe and True in (
                operation + cipher.lower() not in vhost[key].lower()
                for cipher, operation in self.__protocols.items()
            )
        else:
            return True in (
                operation + cipher.lower() not in vhost[key].lower()
                for cipher, operation in self.__protocols.items()
            )  # is vulnerable if True


class Parse_configuration_ciphers(Config_base):
    def __init__(self, openssl: str, ciphers: list):
        self.__openssl = openssl
        self.__ciphers = ciphers
        self.__key = "SSLCipherSuite"
        Validator([(openssl, str), (ciphers, list)])

    def is_empty(self, vhost):
        return self.__key not in vhost or not vhost[self.__key]

    def fix(self, vhost):
        key = self.__key
        v = Validator()
        if key not in vhost:
            vhost[key] = ""
        for cipher in self.__ciphers:
            v.string(cipher)
            vhost[key] = f"{vhost[key]}{':' if vhost[key] else ''}!{cipher.upper()}"

    def condition(self, vhost, openssl: str = None, ignore_openssl=False):
        key = self.__key
        openssl_greater_than = self.__openssl
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

            return not is_safe and True in (
                "!" + cipher.lower() not in vhost[key].lower()
                for cipher in self.__ciphers
            )
        else:
            return True in (
                "!" + cipher.lower() not in vhost[key].lower()
                for cipher in self.__ciphers
            )  # is vulnerable if True
