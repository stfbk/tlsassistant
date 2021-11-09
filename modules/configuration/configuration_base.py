from enum import Enum
from ssl import OPENSSL_VERSION
import logging
from utils.validation import Validator


class OpenSSL:
    """
    OpenSSL version comparison class.
    """

    VERSION = OPENSSL_VERSION.split()[1]

    def less_than(self, ver1, ver2=VERSION):
        """
        Compare two OpenSSL versions, return True if ver1 < ver2.

        :param ver1: OpenSSL version string.
        :type ver1: str
        :param ver2: OpenSSL version string.
        :type ver2: str
        :default ver2: OpenSSL system version.
        :return: True if ver1 < ver2, else False.
        :rtype: bool
        """
        return self.__compare(ver1, ver2)

    def greater_than(self, ver1, ver2=VERSION):
        """
        Compare two OpenSSL versions, return True if ver1 >= ver2.

        :param ver1: OpenSSL version string.
        :type ver1: str
        :param ver2: OpenSSL version string.
        :type ver2: str
        :default ver2: OpenSSL system version.
        :return: True if ver1 < ver2, else False.
        :rtype: bool
        """
        return self.__compare(ver1, ver2, reverse=True)

    def is_safe(self, ver1, ver2=VERSION):
        """
        Compare two OpenSSL versions, alias for less_than.

        :param ver1: OpenSSL version string.
        :type ver1: str
        :param ver2: OpenSSL version string.
        :type ver2: str
        :default ver2: OpenSSL system version.
        :return: True if ver1 < ver2, else False.
        :rtype: bool
        """
        return self.less_than(ver1, ver2)

    def __compare(self, ver1, ver2, reverse=False):
        """
        Internal method to compare two OpenSSL versions.

        :param ver1: OpenSSL version string.
        :type ver1: str
        :param ver2: OpenSSL version string.
        :type ver2: str
        :param reverse: Reverse the order of ver1 and ver2.
        :type reverse: bool
        :return: ver1 < ver2 if reverse is False else ver1 > ver2.
        :rtype: bool
        :raise: AssertionError if length of ver1 and ver2 is different than 5 or 6 chars.

        """

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
    """
    Type of configuration.
    """

    NONE = 0
    HTTP = 80
    SSL = 443


class Config_base:
    """
    Interface for configuration base.
    """

    openSSL = OpenSSL()
    VHOST_USE = Type.NONE

    def condition(self, vhost):
        """
        Dummy condition method.

        :param vhost: VirtualHost object.
        :type vhost: :class:`~letsencrypt_apache.obj.VirtualHost`
        :returns: True if vhost is vulnerable.
        :rtype: bool
        :raise: NotImplementedError if method is not implemented.
        """
        raise NotImplementedError

    def fix(self, vhost):
        """
        Dummy fix method.

        :param vhost: VirtualHost object.
        :type vhost: :class:`~letsencrypt_apache.obj.VirtualHost`
        :raise: NotImplementedError if method is not implemented.
        """
        raise NotImplementedError

    def is_empty(self, vhost):
        """
        Dummy empty method.

        :param vhost: VirtualHost object.
        :type vhost: :class:`~letsencrypt_apache.obj.VirtualHost`
        :returns: True if vhost doesn't have the contextual VirtualHost directive.
        :rtype: bool
        :raise: NotImplementedError if method is not implemented.
        """
        raise NotImplementedError


class Parse_configuration_protocols(Config_base):
    """
    Check if vhost is vulnerable to TLS SSLProtocol bad configuration.
    """

    def is_empty(self, vhost):
        """
        Check if vhost doesn't have the contextual directive.

        :param vhost: VirtualHost object.
        :type vhost: :class:`~letsencrypt_apache.obj.VirtualHost`
        :returns: True if vhost doesn't have the contextual directive.
        :rtype: bool
        """
        return self.__key not in vhost or not vhost[self.__key]

    def is_tls(self, vhost, version=3):
        """
        Check if vhost is using only the TLS version x.

        :param vhost: VirtualHost object.
        :type vhost: :class:`~letsencrypt_apache.obj.VirtualHost`
        :param version: TLS version to check.
        :type version: int
        :returns: True if vhost is using ONLY the TLS version x.
        :rtype: bool
        """
        return (
                "SSLProtocol" in vhost
                and vhost["SSLProtocol"].lower() == f"tlsv1.{version}"
        )

    def __init__(self, openssl: str, protocols: dict):
        """
        :param openssl: OpenSSL version.
        :type openssl: str
        :param protocols: TLS/SSL protocols to check.
        :type protocols: dict
        """
        self.__openssl = openssl
        self.__protocols = protocols
        self.__key = "SSLProtocol"
        Validator([(openssl, str), (protocols, dict)])

    def fix(self, vhost):
        """
        Fix TLS/SSL protocol bad configuration.

        :param vhost: VirtualHost object.
        :type vhost: :class:`~letsencrypt_apache.obj.VirtualHost`
        """
        key = self.__key
        backup = vhost[key] if key in vhost else ""
        v = Validator()
        for cipher, operation in self.__protocols.items():
            v.string(cipher)
            vhost[key] = (
                f"{(vhost[key] if key in vhost and vhost[key] else 'ALL ')}"
                f"{' ' if key in vhost and vhost[key] else ''}{operation}{cipher}"
            )
        return {'before': f"{key} {backup}" if backup else "", 'after': f"{key} {vhost[key]}"}

    def condition(self, vhost, openssl: str = None, ignore_openssl=False):
        """
        Check if vhost is vulnerable to TLS SSLProtocol bad configuration.

        :param vhost: VirtualHost object.
        :type vhost: :class:`~letsencrypt_apache.obj.VirtualHost`
        :param openssl: OpenSSL version.
        :type openssl: str
        :param ignore_openssl: Ignore OpenSSL version.
        :type ignore_openssl: bool
        :returns: True if vhost is vulnerable to TLS SSLProtocol bad configuration.
        :rtype: bool
        """

        if self.is_tls(vhost, version=3):
            logging.debug("TLSv1.3 Detected as mutually allowed.")
            return False
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
    """
    Check if vhost is vulnerable to misconfigured TLS cipher.
    """

    def __init__(self, openssl: str, ciphers: list):
        self.__openssl = openssl
        self.__ciphers = ciphers
        self.__key = "SSLCipherSuite"
        Validator([(openssl, str), (ciphers, list)])

    def is_tls(self, vhost, version=3):
        """
        Check if vhost is using ONLY the TLS version x.

        :param vhost: VirtualHost object.
        :type vhost: :class:`~letsencrypt_apache.obj.VirtualHost`
        :param version: TLS version to check.
        :type version: int
        :returns: True if vhost is using ONLY the TLS version x.
        :rtype: bool
        """
        return (
                "SSLProtocol" in vhost
                and vhost["SSLProtocol"].lower() == f"tlsv1.{version}"
        )

    def is_empty(self, vhost):
        """
        Check if vhost doesn't have the contextual directive.

        :param vhost: VirtualHost object.
        :type vhost: :class:`~letsencrypt_apache.obj.VirtualHost`
        :returns: True if vhost doesn't have the contextual directive.
        :rtype: bool
        """
        return self.__key not in vhost or not vhost[self.__key]

    def fix(self, vhost):
        """
        Fix misconfigured TLS cipher in vhost.

        :param vhost: VirtualHost object.
        :type vhost: :class:`~letsencrypt_apache.obj.VirtualHost`
        """
        key = self.__key
        v = Validator()
        backup = vhost[key] if key in vhost else ""
        for cipher in self.__ciphers:
            v.string(cipher)
            vhost[key] = (
                f"{vhost[key] if key in vhost and vhost[key] else ''}"
                f"{':' if key in vhost and vhost[key] else ''}!{cipher.upper()}"
            )
        return {'before': f"{key} {backup}" if backup else "", 'after': f"{key} {vhost[key]}"}

    def condition(self, vhost, openssl: str = None, ignore_openssl=False):
        """
        Check if vhost is vulnerable to misconfigured TLS cipher.

        :param vhost: VirtualHost object.
        :type vhost: :class:`~letsencrypt_apache.obj.VirtualHost`
        :param openssl: OpenSSL version.
        :type openssl: str
        :param ignore_openssl: Ignore OpenSSL version.
        :type ignore_openssl: bool
        :returns: True if vhost is vulnerable to misconfigured TLS cipher.
        :rtype: bool

        """
        if self.is_tls(vhost, version=3):
            logging.debug("TLSv1.3 Detected as mutually allowed.")
            return False
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
    """
    Check if vhost is vulnerable to misconfigured TLS strict security.
    """

    VHOST_USE = Type.SSL

    def __init__(self):
        self.__key = "Header"

    def is_empty(self, vhost):
        """
        Check if vhost doesn't have the header directive.

        :param vhost: VirtualHost object.
        :type vhost: :class:`~letsencrypt_apache.obj.VirtualHost`
        :returns: True if vhost doesn't have the header directive.
        :rtype: bool
        """
        return self.__key not in vhost or not vhost[self.__key]

    def fix(self, vhost):
        """
        Fix misconfigured TLS strict security in vhost.

        :param vhost: VirtualHost object.
        :type vhost: :class:`~letsencrypt_apache.obj.VirtualHost`
        """
        key = self.__key
        backup = vhost[key] if key in vhost else ""
        to_add = 'always set Strict-Transport-Security "max-age=63072000"'
        if key in vhost:
            vhost[key] += f";{to_add}"
        else:
            vhost[key] = to_add
        return {'before': f"{key} {backup}" if backup else "", 'after': f"{key} {vhost[key]}"}

    def condition(self, vhost, openssl: str = None, ignore_openssl=False):
        """
        Check if vhost is vulnerable to misconfigured TLS strict security.

        :param vhost: VirtualHost object.
        :type vhost: :class:`~letsencrypt_apache.obj.VirtualHost`
        :param openssl: OpenSSL version.
        :type openssl: str
        :param ignore_openssl: Ignore OpenSSL version.
        :type ignore_openssl: bool
        :returns: True if vhost is vulnerable to misconfigured TLS strict security.
        :rtype: bool
        """

        return (
                self.__key not in vhost
                or "Strict-Transport-Security" not in vhost[self.__key]
        )  # vulnerable if True


class Parse_configuration_checks_compression(Config_base):
    """
    Check if vhost is vulnerable to misconfigured TLS compression.

    :param vhost: VirtualHost object.
    :type vhost: :class:`~letsencrypt_apache.obj.VirtualHost`
    """

    VHOST_USE = Type.NONE

    def __init__(self, openssl: str):
        self.__openssl = openssl
        self.__key = "SSLCompression"
        self.__value = "Off"
        Validator([(openssl, str)])

    def is_tls(self, vhost, version=3):
        """
        Check if vhost is using only a specific version of TLS.

        :param vhost: VirtualHost object.
        :type vhost: :class:`~letsencrypt_apache.obj.VirtualHost`
        :param version: TLS version.
        :type version: int
        :returns: True if vhost is using only a specific version of TLS.
        :rtype: bool
        """
        return (
                "SSLProtocol" in vhost
                and vhost["SSLProtocol"].lower() == f"tlsv1.{version}"
        )

    def is_empty(self, vhost):
        """
        Check if vhost doesn't have the SSLCompression directive.

        :param vhost: VirtualHost object.
        :type vhost: :class:`~letsencrypt_apache.obj.VirtualHost`
        :returns: True if vhost doesn't have the SSLCompression directive.
        :rtype: bool
        """
        return self.__key not in vhost or not vhost[self.__key]

    def fix(self, vhost):
        """
        Fix misconfigured TLS compression in vhost.

        :param vhost: VirtualHost object.
        :type vhost: :class:`~letsencrypt_apache.obj.VirtualHost`
        """
        key = self.__key
        backup = vhost[key] if key in vhost else ""
        vhost[key] = self.__value
        return {'before': f"{key} {backup}" if backup else "", 'after': f"{key} {vhost[key]}"}

    def condition(self, vhost, openssl: str = None, ignore_openssl=False):
        """
        Check if vhost is vulnerable to misconfigured TLS compression.

        :param vhost: VirtualHost object.
        :type vhost: :class:`~letsencrypt_apache.obj.VirtualHost`
        :param openssl: OpenSSL version.
        :type openssl: str
        :param ignore_openssl: Ignore OpenSSL version.
        :type ignore_openssl: bool
        :returns: True if vhost is vulnerable to misconfigured TLS compression.
        :rtype: bool
        """
        if self.is_tls(vhost, version=3):
            logging.debug("TLSv1.3 Detected as mutually allowed.")
            return False
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
    """
    Check if vhost is vulnerable to misconfigured TLS redirect.
    """

    VHOST_USE = Type.HTTP

    def __init__(self):
        self.__keys = ["RewriteEngine", "RewriteRule"]

    def is_empty(self, vhost):
        """
        Check if vhost doesn't have the RewriteEngine and RewriteRule directives.

        :param vhost: VirtualHost object.
        :type vhost: :class:`~letsencrypt_apache.obj.VirtualHost`
        :returns: True if vhost doesn't have the RewriteEngine and RewriteRule directives.
        :rtype: bool
        """
        return True in (key not in vhost for key in self.__keys)

    def fix(self, vhost):
        """
        Fix misconfigured TLS redirect in vhost.

        :param vhost: VirtualHost object.
        :type vhost: :class:`~letsencrypt_apache.obj.VirtualHost`
        """
        RewriteEngine, RewriteRule = self.__keys
        backup_rewrite_engine = vhost[RewriteEngine] if RewriteEngine in vhost else ""
        backup_rewrite_rule = vhost[RewriteRule] if RewriteRule in vhost else ""
        vhost[RewriteEngine] = "on"
        vhost[RewriteRule] = "^(.*)$ https://%{HTTP_HOST}$1 [R=301,L]"
        return {
            'before': {
                'RewriteEngine': backup_rewrite_engine,
                'RewriteRule': backup_rewrite_rule
            },
            'after': {
                'RewriteEngine': vhost[RewriteEngine],
                'RewriteRule': vhost[RewriteRule]
            }
        }

    def condition(self, vhost, openssl=None, ignore_openssl=False):
        """
        Check if vhost is vulnerable to misconfigured TLS redirect.

        :param vhost: VirtualHost object.
        :type vhost: :class:`~letsencrypt_apache.obj.VirtualHost`
        :param openssl: OpenSSL version.
        :type openssl: str
        :param ignore_openssl: Ignore OpenSSL version.
        :type ignore_openssl: bool
        :returns: True if vhost is vulnerable to misconfigured TLS redirect.
        :rtype: bool
        """
        RewriteEngine, RewriteRule = self.__keys
        return (
                RewriteEngine not in vhost
                or RewriteRule not in vhost
                or vhost[RewriteEngine] != "on"
                or vhost[RewriteRule] != "^(.*)$ https://%{HTTP_HOST}$1 [R=301,L]"
        )  # vulnerable if True
