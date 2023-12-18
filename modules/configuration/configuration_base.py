from ssl import OPENSSL_VERSION
import logging
from utils.type import PortType, WebserverType
from utils.validation import Validator

from modules.configuration.apache.apache_configuration_base import *
from modules.configuration.nginx.nginx_configuration_base import *


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


class Config_base:
    """
    Interface for configuration base.
    """

    openSSL = OpenSSL()
    VHOST_USE = PortType.NONE

    def set_webserver(self, webserver: WebserverType):
        """
        Dummy set webserver type.

        :param webserver: Webserver type.
        :type webserver: :class:`~letsencrypt_apache.configuration.WebserverType`
        """
        raise NotImplementedError

    def condition(self, vhost):
        """
        Dummy condition method.

        :param vhost: VirtualHost object.
        :type vhost: dict
        :returns: True if vhost is vulnerable.
        :rtype: bool
        :raise: NotImplementedError if method is not implemented.
        """
        raise NotImplementedError

    def fix(self, vhost):
        """
        Dummy fix method.

        :param vhost: VirtualHost object.
        :type vhost: dict
        :raise: NotImplementedError if method is not implemented.
        """
        raise NotImplementedError

    def is_empty(self, vhost):
        """
        Dummy empty method.

        :param vhost: VirtualHost object.
        :type vhost: dict
        :returns: True if vhost doesn't have the contextual VirtualHost directive.
        :rtype: bool
        :raise: NotImplementedError if method is not implemented.
        """
        raise NotImplementedError

class Parse_configuration_protocols(Config_base):
    """
    Check if vhost is vulnerable to TLS SSLProtocol bad configuration.
    """

    def __init__(self, openssl: str, protocols: dict):
        """
        :param openssl: OpenSSL version.
        :type openssl: str
        :param protocols: TLS/SSL protocols to check.
        :type protocols: dict
        """
        self.__openssl = openssl
        self.__protocols = protocols
        Validator([(openssl, str), (protocols, dict)])
        self.__execution_class = None
        self.__webserver_type = WebserverType.AUTO

    def set_webserver(self, webserver: WebserverType):
        self.__webserver_type = webserver
        if webserver == WebserverType.APACHE:
            self.__execution_class = Apache_parse_configuration_protocols(self.__openssl, self.__protocols, self.openSSL)
        elif webserver == WebserverType.NGINX: 
            self.__execution_class = Nginx_parse_configuration_protocols(self.__openssl, self.__protocols, self.openSSL)

    def is_empty(self, vhost):
        """
        Check if vhost doesn't have the contextual directive.

        :param vhost: VirtualHost object.
        :type vhost: dict
        :returns: True if vhost doesn't have the contextual directive.
        :rtype: bool
        """
        assert self.__execution_class is not None, "Webserver type not set."
        return self.__execution_class.is_empty(vhost)

    def is_tls(self, vhost, version=3):
        """
        Check if vhost is using only the TLS version x.

        :param vhost: VirtualHost object.
        :type vhost: dict
        :param version: TLS version to check.
        :type version: int
        :returns: True if vhost is using ONLY the TLS version x.
        :rtype: bool
        """
        assert self.__execution_class is not None, "Webserver type not set."
        return self.__execution_class.is_tls(vhost, version)

    def fix(self, vhost):
        """
        Fix TLS/SSL protocol bad configuration.

        :param vhost: VirtualHost object.
        :type vhost: dict
        """
        assert self.__execution_class is not None, "Webserver type not set."
        return self.__execution_class.fix(vhost)

    def condition(self, vhost, openssl: str = None, ignore_openssl=False):
        """
        Check if vhost is vulnerable to TLS SSLProtocol bad configuration.

        :param vhost: VirtualHost object.
        :type vhost: dict
        :param openssl: OpenSSL version.
        :type openssl: str
        :param ignore_openssl: Ignore OpenSSL version.
        :type ignore_openssl: bool
        :returns: True if vhost is vulnerable to TLS SSLProtocol bad configuration.
        :rtype: bool
        """
        assert self.__execution_class is not None, "Webserver type not set."
        return self.__execution_class.condition(vhost, openssl, ignore_openssl)


class Parse_configuration_ciphers(Config_base):
    """
    Check if vhost is vulnerable to misconfigured TLS cipher.
    """

    VHOST_USE = PortType.SSL

    def __init__(self, openssl: str, ciphers: list):
        self.__openssl = openssl
        self.__ciphers = ciphers
        Validator([(openssl, str), (ciphers, list)])
        self.__execution_class = None
        self.__webserver_type = WebserverType.AUTO

    def set_webserver(self, webserver: WebserverType):
        self.__webserver_type = webserver
        if webserver == WebserverType.APACHE:
            self.__execution_class = Apache_parse_configuration_ciphers(self.__openssl, self.__ciphers, self.openSSL)
        elif webserver == WebserverType.NGINX: 
            self.__execution_class = Nginx_parse_configuration_ciphers(self.__openssl, self.__ciphers, self.openSSL)

    def is_tls(self, vhost, version=3):
        """
        Check if vhost is using ONLY the TLS version x.

        :param vhost: VirtualHost object.
        :type vhost: dict
        :param version: TLS version to check.
        :type version: int
        :returns: True if vhost is using ONLY the TLS version x.
        :rtype: bool
        """
        assert self.__execution_class is not None, "Webserver type not set."
        return self.__execution_class.is_tls(vhost, version)

    def is_empty(self, vhost):
        """
        Check if vhost doesn't have the contextual directive.

        :param vhost: VirtualHost object.
        :type vhost: dict
        :returns: True if vhost doesn't have the contextual directive.
        :rtype: bool
        """
        assert self.__execution_class is not None, "Webserver type not set."
        return self.__execution_class.is_empty(vhost)

    def fix(self, vhost):
        assert self.__execution_class is not None, "Webserver type not set."
        return self.__execution_class.fix(vhost)

    def condition(self, vhost, openssl: str = None, ignore_openssl=False):
        """
        Check if vhost is vulnerable to misconfigured TLS cipher.

        :param vhost: VirtualHost object.
        :type vhost: dict
        :param openssl: OpenSSL version.
        :type openssl: str
        :param ignore_openssl: Ignore OpenSSL version.
        :type ignore_openssl: bool
        :returns: True if vhost is vulnerable to misconfigured TLS cipher.
        :rtype: bool

        """
        assert self.__execution_class is not None, "Webserver type not set."
        return self.__execution_class.condition(vhost, openssl, ignore_openssl)


class Parse_configuration_strict_security(Config_base):
    """
    Check if vhost is vulnerable to misconfigured TLS strict security.
    """

    VHOST_USE = PortType.SSL

    def __init__(self):
        self.__execution_class = None
        self.__webserver_type = WebserverType.AUTO

    def set_webserver(self, webserver: WebserverType):
        self.__webserver_type = webserver
        if webserver == WebserverType.APACHE:
            self.__execution_class = Apache_parse_configuration_strict_security()
        elif webserver == WebserverType.NGINX: 
            self.__execution_class = Nginx_parse_configuration_strict_security()

    def is_empty(self, vhost):
        """
        Check if vhost doesn't have the header directive.

        :param vhost: VirtualHost object.
        :type vhost: dict
        :returns: True if vhost doesn't have the header directive.
        :rtype: bool
        """
        assert self.__execution_class is not None, "Webserver type not set."
        return self.__execution_class.is_empty(vhost)

    def fix(self, vhost):
        """
        Fix misconfigured TLS strict security in vhost.

        :param vhost: VirtualHost object.
        :type vhost: dict
        """
        assert self.__execution_class is not None, "Webserver type not set."
        return self.__execution_class.fix(vhost)

    def condition(self, vhost, openssl: str = None, ignore_openssl=False):
        """
        Check if vhost is vulnerable to misconfigured TLS strict security.

        :param vhost: VirtualHost object.
        :type vhost: dict
        :param openssl: OpenSSL version.
        :type openssl: str
        :param ignore_openssl: Ignore OpenSSL version.
        :type ignore_openssl: bool
        :returns: True if vhost is vulnerable to misconfigured TLS strict security.
        :rtype: bool
        """
        assert self.__execution_class is not None, "Webserver type not set."
        return self.__execution_class.condition(vhost, openssl, ignore_openssl)


class Parse_configuration_checks_compression(Config_base):
    """
    Check if vhost is vulnerable to misconfigured TLS compression.

    :param vhost: VirtualHost object.
    :type vhost: dict
    """

    VHOST_USE = PortType.NONE

    def __init__(self, openssl: str):
        self.__openssl = openssl
        Validator([(openssl, str)])
        self.__execution_class = None
        self.__webserver_type = WebserverType.AUTO

    def set_webserver(self, webserver: WebserverType):
        self.__webserver_type = webserver
        if webserver == WebserverType.APACHE:
            self.__execution_class = Apache_parse_configuration_checks_compression(self.__openssl, self.openSSL)
        elif webserver == WebserverType.NGINX: 
            self.__execution_class = Nginx_parse_configuration_checks_compression(self.__openssl, self.openSSL)


    def is_tls(self, vhost, version=3):
        """
        Check if vhost is using only a specific version of TLS.

        :param vhost: VirtualHost object.
        :type vhost: dict
        :param version: TLS version.
        :type version: int
        :returns: True if vhost is using only a specific version of TLS.
        :rtype: bool
        """
        assert self.__execution_class is not None, "Webserver type not set."
        return self.__execution_class.is_tls(vhost, version)

    def is_empty(self, vhost):
        """
        Check if vhost doesn't have the SSLCompression directive.

        :param vhost: VirtualHost object.
        :type vhost: dict
        :returns: True if vhost doesn't have the SSLCompression directive.
        :rtype: bool
        """
        assert self.__execution_class is not None, "Webserver type not set."
        return self.__execution_class.is_empty(vhost)

    def fix(self, vhost):
        """
        Fix misconfigured TLS compression in vhost.

        :param vhost: VirtualHost object.
        :type vhost: dict
        """
        assert self.__execution_class is not None, "Webserver type not set."
        return self.__execution_class.fix(vhost)

    def condition(self, vhost, openssl: str = None, ignore_openssl=False):
        """
        Check if vhost is vulnerable to misconfigured TLS compression.

        :param vhost: VirtualHost object.
        :type vhost: dict
        :param openssl: OpenSSL version.
        :type openssl: str
        :param ignore_openssl: Ignore OpenSSL version.
        :type ignore_openssl: bool
        :returns: True if vhost is vulnerable to misconfigured TLS compression.
        :rtype: bool
        """
        assert self.__execution_class is not None, "Webserver type not set."
        return self.__execution_class.condition(vhost, openssl, ignore_openssl)

class Parse_configuration_checks_redirect(Config_base):
    """
    Check if vhost is vulnerable to misconfigured TLS redirect.
    """

    VHOST_USE = PortType.HTTP

    def __init__(self):
        self.__execution_class = None
        self.__webserver_type = WebserverType.AUTO

    def set_webserver(self, webserver: WebserverType):
        self.__webserver_type = webserver
        if webserver == WebserverType.APACHE:
            self.__execution_class = Apache_parse_configuration_checks_redirect()
        elif webserver == WebserverType.NGINX: 
            self.__execution_class = Nginx_parse_configuration_checks_redirect()

    def is_empty(self, vhost):
        """
        Check if vhost doesn't have the RewriteEngine and RewriteRule directives.

        :param vhost: VirtualHost object.
        :type vhost: dict
        :returns: True if vhost doesn't have the RewriteEngine and RewriteRule directives.
        :rtype: bool
        """
        assert self.__execution_class is not None, "Webserver type not set."
        return self.__execution_class.is_empty(vhost)

    def fix(self, vhost):
        """
        Fix misconfigured TLS redirect in vhost.

        :param vhost: VirtualHost object.
        :type vhost: dict
        """
        assert self.__execution_class is not None, "Webserver type not set."
        return self.__execution_class.fix(vhost)

    def condition(self, vhost, openssl=None, ignore_openssl=False):
        """
        Check if vhost is vulnerable to misconfigured TLS redirect.

        :param vhost: VirtualHost object.
        :type vhost: dict
        :param openssl: OpenSSL version.
        :type openssl: str
        :param ignore_openssl: Ignore OpenSSL version.
        :type ignore_openssl: bool
        :returns: True if vhost is vulnerable to misconfigured TLS redirect.
        :rtype: bool
        """
        assert self.__execution_class is not None, "Webserver type not set."
        return self.__execution_class.condition(vhost, openssl, ignore_openssl)
