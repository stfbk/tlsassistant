import logging
from utils.validation import Validator


class Nginx_parse_configuration_protocols():
    """
    Check if vhost is vulnerable to TLS SSLProtocol bad configuration.
    """

    def __init__(self, openssl: str, protocols: dict, openssl_class):
        """
        :param openssl: OpenSSL version.
        :type openssl: str
        :param protocols: TLS/SSL protocols to check.
        :type protocols: dict
        :param openssl_class: OpenSSL class from "super".
        :type openssl_class: OpenSSL
        """
        self.__openssl = openssl
        self.__protocols = protocols
        self.openSSL = openssl_class
        self.__key = "ssl_protocols"
        Validator([(openssl, str), (protocols, dict)])

    def is_empty(self, vhost):
        """
        Check if vhost doesn't have the contextual directive.

        :param vhost: "VirtualHost" object.
        :type vhost: dict
        :returns: True if vhost doesn't have the contextual directive.
        :rtype: bool
        """
        return self.__key not in vhost or not vhost[self.__key]

    def is_tls(self, vhost, version=3):
        """
        Check if vhost is using only the TLS version x.

        :param vhost: "VirtualHost" object.
        :type vhost: dict
        :param version: TLS version to check.
        :type version: int
        :returns: True if vhost is using ONLY the TLS version x.
        :rtype: bool
        """
        return (
            "ssl_protocols" in vhost
            and len(vhost["ssl_protocols"]) == 1
            and any(protocol.lower() == f"tlsv1.{version}" for protocol in vhost["ssl_protocols"])
        )

    def fix(self, vhost):
        """
        Fix TLS/SSL protocol bad configuration.

        :param vhost: "VirtualHost" object.
        :type vhost: dict
        """
        key = self.__key
        ciphers = ['SSLv2', 'SSLv3','TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']
        ciphers_default = ['TLSv1', 'TLSv1.1', 'TLSv1.2']
        backup = vhost[key].copy() if key in vhost else []
        v = Validator()
        for cipher, operation in self.__protocols.items():
            v.string(cipher)
            if operation == '-':
                if key in vhost:
                    if len(vhost[key]) == 1:
                        if vhost[key][0].lower() == cipher.lower():
                            vhost[key] = ciphers_default
                    elif cipher in vhost[key]:
                        vhost[key].remove(cipher)
                else:
                    vhost[key] = ciphers_default
            else:
                raise NotImplementedError
        return {
            "before": f"{key} {backup}" if backup else "",
            "after": f"{key} {vhost[key]}",
        }

    def condition(self, vhost, openssl: str = None, ignore_openssl=False):
        """
        Check if vhost is vulnerable to TLS SSLProtocol bad configuration.

        :param vhost: "VirtualHost" object.
        :type vhost: dict
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
                cipher.lower()
                not in ([protocol.lower() for protocol in vhost[key]] if key in vhost else "")
                for cipher, operation in self.__protocols.items()
            )
        else:
            # Syntax:	ssl_protocols [SSLv2] [SSLv3] [TLSv1] [TLSv1.1] [TLSv1.2] [TLSv1.3];
            # Default:	ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
            return True in (
                cipher.lower()
                not in ([protocol.lower() for protocol in vhost[key]] if key in vhost else "")
                for cipher, operation in self.__protocols.items()
            )  # is vulnerable if True

class Nginx_parse_configuration_ciphers():
    """
    Check if vhost is vulnerable to misconfigured TLS cipher.
    """

    def __init__(self, openssl: str, ciphers: list, openssl_class):
        """
        :param openssl: OpenSSL version.
        :type openssl: str
        :param ciphers: ciphers to check.
        :type ciphers: dict
        :param openssl_class: OpenSSL class from "super".
        :type openssl_class: OpenSSL
        """
        self.__openssl = openssl
        self.__ciphers = ciphers
        self.openSSL = openssl_class
        self.__key = "ssl_ciphers"
        Validator([(openssl, str), (ciphers, list)])

    def is_tls(self, vhost, version=3):
        """
        Check if vhost is using ONLY the TLS version x.

        :param vhost: "VirtualHost" object.
        :type vhost: dict
        :param version: TLS version to check.
        :type version: int
        :returns: True if vhost is using ONLY the TLS version x.
        :rtype: bool
        """
        return (
            "ssl_protocols" in vhost
            and len(vhost["ssl_protocols"]) == 1
            and any(protocol.lower() == f"tlsv1.{version}" for protocol in vhost["ssl_protocols"])
        )

    def is_empty(self, vhost):
        """
        Check if vhost doesn't have the contextual directive.

        :param vhost: "VirtualHost" object.
        :type vhost: dict
        :returns: True if vhost doesn't have the contextual directive.
        :rtype: bool
        """
        return self.__key not in vhost or not vhost[self.__key]

    def fix(self, vhost):
        """
        Fix misconfigured TLS cipher in vhost.

        :param vhost: "VirtualHost" object.
        :type vhost: dict
        """
        key = self.__key
        v = Validator()
        ciphers_default = 'HIGH:!aNULL:!MD5'
        backup = vhost[key].copy() if key in vhost else []
        for cipher in self.__ciphers:
            v.string(cipher)
            if key in vhost:
                if len(vhost[key]) == 1:
                    # ssl_ciphers directive has only one argument
                    vhost[key][0] += f":!{cipher.upper()}"
                else: # len could be only 0
                    vhost[key] = [f'{ciphers_default}:!{cipher.upper()}']
            else:
                vhost[key] = [f'{ciphers_default}:!{cipher.upper()}']
        
        return {
            "before": f"{key} {backup}" if backup else "",
            "after": f"{key} {vhost[key]}",
        }

    def condition(self, vhost, openssl: str = None, ignore_openssl=False):
        """
        Check if vhost is vulnerable to misconfigured TLS cipher.

        :param vhost: "VirtualHost" object.
        :type vhost: dict
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
                "!" + cipher.lower() not in (vhost[key][0].lower() if (key in vhost and len(vhost[key]) != 0) else "")
                for cipher in self.__ciphers
            )
        else:
            # Syntax:	ssl_ciphers ciphers;
            # Default:	ssl_ciphers HIGH:!aNULL:!MD5;
            # The ciphers are specified in the format understood by the OpenSSL library
            return True in (
                "!" + cipher.lower() not in (vhost[key][0].lower() if (key in vhost and len(vhost[key]) != 0) else "")
                for cipher in self.__ciphers
            )  # is vulnerable if True

class Nginx_parse_configuration_strict_security():
    """
    Check if vhost is vulnerable to misconfigured TLS strict security.
    """

    def __init__(self):
        self.__key = "add_header"

    def is_empty(self, vhost):
        """
        Check if vhost doesn't have the header directive.

        :param vhost: "VirtualHost" object.
        :type vhost: dict
        :returns: True if vhost doesn't have the header directive.
        :rtype: bool
        """
        return self.__key not in vhost or not vhost[self.__key]

    def fix(self, vhost):
        """
        Fix misconfigured TLS strict security in vhost.

        :param vhost: "VirtualHost" object.
        :type vhost: dict
        """
        key = self.__key
        backup = vhost[key].copy() if key in vhost else []
        to_add = ['Strict-Transport-Security', 'max-age=31536000; includeSubdomains; preload']
        if key in vhost:
            vhost[key] = [vhost[key]]
            vhost[key].append(to_add)
        else:
            vhost[key] = to_add
        return {
            "before": f"{key} {backup}" if backup else "",
            "after": f"{key} {vhost[key]}",
        }

    def condition(self, vhost, openssl: str = None, ignore_openssl=False):
        """
        Check if vhost is vulnerable to misconfigured TLS strict security.

        :param vhost: "VirtualHost" object.
        :type vhost: dict
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

class Nginx_parse_configuration_checks_compression():
    """
    Check if vhost is vulnerable to misconfigured TLS compression.

    :param vhost: "VirtualHost" object.
    :type vhost: dict
    """

    def __init__(self, openssl: str, openssl_class):
        """
        :param openssl: OpenSSL version.
        :type openssl: str
        :param openssl_class: OpenSSL class from "super".
        :type openssl_class: OpenSSL
        """
        self.__openssl = openssl
        self.__key = "ssl_compression"
        self.openSSL = openssl_class
        self.__value = "Off"
        Validator([(openssl, str)])

    def is_tls(self, vhost, version=3):
        """
        Check if vhost is using only a specific version of TLS.

        :param vhost: "VirtualHost" object.
        :type vhost: dict
        :param version: TLS version.
        :type version: int
        :returns: True if vhost is using only a specific version of TLS.
        :rtype: bool
        """
        return (
            "ssl_protocols" in vhost
            and len(vhost["ssl_protocols"]) == 1
            and any(protocol.lower() == f"tlsv1.{version}" for protocol in vhost["ssl_protocols"])
        )

    def is_empty(self, vhost):
        """
        Check if vhost doesn't have the SSLCompression directive.

        :param vhost: "VirtualHost" object.
        :type vhost: dict
        :returns: True if vhost doesn't have the SSLCompression directive.
        :rtype: bool
        """
        return True

    def fix(self, vhost):
        """
        Fix misconfigured TLS compression in vhost.

        :param vhost: "VirtualHost" object.
        :type vhost: dict
        """
        # no directive fix available for nginx 
        return {}

    def condition(self, vhost, openssl: str = None, ignore_openssl=False):
        """
        Check if vhost is vulnerable to misconfigured TLS compression.

        :param vhost: "VirtualHost" object.
        :type vhost: dict
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
        
        # nginx non ha direttive per ssl compression, dipende solo dalla versione utilizzata
        if not ignore_openssl:
            if openssl:
                is_safe = self.openSSL.is_safe(ver1=openssl_greater_than, ver2=openssl)
            else:
                is_safe = self.openSSL.is_safe(ver1=openssl_greater_than)

            return not is_safe

        else:
            return True  # potentially always vulnerable without OpenSSL version check
            # is vulnerable if True

class Nginx_parse_configuration_checks_redirect():
    """
    Check if vhost is vulnerable to misconfigured TLS redirect.
    """

    def __init__(self):
        self.__key = "return";

    def is_empty(self, vhost):
        """
        Check if vhost doesn't have the 'return' directive.

        :param vhost: "VirtualHost" object.
        :type vhost: dict
        :returns: True if vhost doesn't have the RewriteEngine and RewriteRule directives.
        :rtype: bool
        """
        return self.__key not in vhost or "301" not in vhost[self.__key]

    def fix(self, vhost):
        """
        Fix misconfigured TLS redirect in vhost.

        :param vhost: "VirtualHost" object.
        :type vhost: dict
        """
        key = self.__key
        backup = vhost[key].copy() if key in vhost else []
        if key not in vhost:
            vhost[key] = ['301', 'https://$host$request_uri']
        else:
            # TODO: Check which one is already here?
            pass
        
        return {
            "before": f"{key} {backup}" if backup else "",
            "after": f"{key} {vhost[key]}"
        }

    def condition(self, vhost, openssl=None, ignore_openssl=False):
        """
        Check if vhost is vulnerable to misconfigured TLS redirect.

        :param vhost: "VirtualHost" object.
        :type vhost: dict
        :param openssl: OpenSSL version.
        :type openssl: str
        :param ignore_openssl: Ignore OpenSSL version.
        :type ignore_openssl: bool
        :returns: True if vhost is vulnerable to misconfigured TLS redirect.
        :rtype: bool
        """
        # Syntax: return_code URL;
        return (
            self.__key not in vhost
            or "301" not in vhost[self.__key]
            or ("301" in vhost[self.__key]
                and "https" not in vhost[self.__key][-1].lower())
        )  # vulnerable if True
