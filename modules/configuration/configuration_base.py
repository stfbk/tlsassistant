from enum import Enum
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


class Type:
    NONE = 0
    HTTP = 80
    SSL = 443


class Config_base:

    openSSL = OpenSSL()
    VHOST_USE = Type.NONE

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
        for cipher, operation in self.__protocols.items():
            v.string(cipher)
            vhost[key] = (
                f"{(vhost[key] if key in vhost and vhost[key] else 'ALL ')}"
                f"{' ' if key in vhost and vhost[key] else ''}{operation}{cipher}"
            )

    def condition(self, vhost, openssl: str = None, ignore_openssl=False):
        key = self.__key
        openssl_greater_than = self.__openssl
        if openssl is None:
            openssl = ""
        Validator([(openssl, str)])
        if not ignore_openssl:
            if openssl:
                is_safe = self.openSSL.is_safe(ver1=openssl_greater_than, ver2=openssl)
            else:
                is_safe = self.openSSL.is_safe(ver1=openssl_greater_than)

            return not is_safe and True in (
                operation + cipher.lower()
                not in (vhost[key].lower() if key in vhost else "")
                for cipher, operation in self.__protocols.items()
            )
        else:
            return True in (
                operation + cipher.lower()
                not in (vhost[key].lower() if key in vhost else "")
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
        for cipher in self.__ciphers:
            v.string(cipher)
            vhost[key] = (
                f"{vhost[key] if key in vhost and vhost[key] else ''}"
                f"{':' if key in vhost and vhost[key] else ''}!{cipher.upper()}"
            )

    def condition(self, vhost, openssl: str = None, ignore_openssl=False):
        key = self.__key
        openssl_greater_than = self.__openssl
        if openssl is None:
            openssl = ""
        Validator([(openssl, str)])
        if not ignore_openssl:
            if openssl:
                is_safe = self.openSSL.is_safe(ver1=openssl_greater_than, ver2=openssl)
            else:
                is_safe = self.openSSL.is_safe(ver1=openssl_greater_than)

            return not is_safe and True in (
                "!" + cipher.lower() not in (vhost[key].lower() if key in vhost else "")
                for cipher in self.__ciphers
            )
        else:
            return True in (
                "!" + cipher.lower() not in (vhost[key].lower() if key in vhost else "")
                for cipher in self.__ciphers
            )  # is vulnerable if True


class Parse_configuration_strict_security(Config_base):
    VHOST_USE = Type.SSL

    def __init__(self):
        self.__key = "Header"

    def is_empty(self, vhost):
        return self.__key not in vhost or not vhost[self.__key]

    def fix(self, vhost):
        key = self.__key
        to_add = 'always set Strict-Transport-Security "max-age=63072000"'
        if key in vhost:
            vhost[key] += f";{to_add}"
        else:
            vhost[key] = to_add

    def condition(self, vhost, openssl: str = None, ignore_openssl=False):
        return (
            self.__key not in vhost
            or "Strict-Transport-Security" not in vhost[self.__key]
        )  # vulnerable if True


class Parse_configuration_checks_compression(Config_base):
    VHOST_USE = Type.NONE

    def __init__(self, openssl: str):
        self.__openssl = openssl
        self.__key = "SSLCompression"
        self.__value = "Off"
        Validator([(openssl, str)])

    def is_empty(self, vhost):
        return self.__key not in vhost or not vhost[self.__key]

    def fix(self, vhost):
        key = self.__key
        vhost[key] = self.__value

    def condition(self, vhost, openssl: str = None, ignore_openssl=False):
        key = self.__key
        openssl_greater_than = self.__openssl
        if openssl is None:
            openssl = ""
        Validator([(openssl, str)])
        if not ignore_openssl:
            if openssl:
                is_safe = self.openSSL.is_safe(ver1=openssl_greater_than, ver2=openssl)
            else:
                is_safe = self.openSSL.is_safe(ver1=openssl_greater_than)
            
            return not is_safe and (key not in vhost or vhost[key] != self.__value)

        else:
            return (
                key not in vhost or vhost[key] != self.__value
            )  # is vulnerable if True


class Parse_configuration_checks_redirect(Config_base):
    VHOST_USE = Type.HTTP

    def __init__(self):
        self.__keys = ["RewriteEngine", "RewriteRule"]

    def is_empty(self, vhost):
        return True in (key not in vhost for key in self.__keys)

    def fix(self, vhost):
        RewriteEngine, RewriteRule = self.__keys
        vhost[RewriteEngine] = "on"
        vhost[RewriteRule] = "^(.*)$ https://%{HTTP_HOST}$1 [R=301,L]"

    def condition(self, vhost, openssl=None, ignore_openssl=False):
        RewriteEngine, RewriteRule = self.__keys
        return (
            RewriteEngine not in vhost
            or RewriteRule not in vhost
            or vhost[RewriteEngine] != "on"
            or vhost[RewriteRule] != "^(.*)$ https://%{HTTP_HOST}$1 [R=301,L]"
        )  # vulnerable if True
