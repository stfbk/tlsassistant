import logging
from utils.validation import Validator


class Apache_parse_configuration_protocols():
    """
    Check if vhost is vulnerable to TLS SSLProtocol bad configuration.
    """

    def __init__(self, openssl: str, protocols: dict, openssl_class):
        """
        :param openssl: OpenSSL version.
        :type openssl: str
        :param protocols: TLS/SSL protocols to check.
        :type protocols: dict
        """
        self.__openssl = openssl
        self.__protocols = protocols
        self.openSSL = openssl_class
        self.__key = "SSLProtocol"
        Validator([(openssl, str), (protocols, dict)])

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
        return {
            "before": f"{key} {backup}" if backup else "",
            "after": f"{key} {vhost[key]}",
        }

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

class Apache_parse_configuration_ciphers():
    """
    Check if vhost is vulnerable to misconfigured TLS cipher.
    """

    def __init__(self, openssl: str, ciphers: list, openssl_class):
        self.__openssl = openssl
        self.__ciphers = ciphers
        self.openSSL = openssl_class
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
        return {
            "before": f"{key} {backup}" if backup else "",
            "after": f"{key} {vhost[key]}",
        }

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

class Apache_parse_configuration_strict_security():
    """
    Check if vhost is vulnerable to misconfigured TLS strict security.
    """

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
        return {
            "before": f"{key} {backup}" if backup else "",
            "after": f"{key} {vhost[key]}",
        }

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

class Apache_parse_configuration_checks_compression():
    """
    Check if vhost is vulnerable to misconfigured TLS compression.

    :param vhost: VirtualHost object.
    :type vhost: :class:`~letsencrypt_apache.obj.VirtualHost`
    """

    def __init__(self, openssl: str, openssl_class):
        self.__openssl = openssl
        self.openSSL = openssl_class
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
        return {
            "before": f"{key} {backup}" if backup else "",
            "after": f"{key} {vhost[key]}",
        }

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

class Apache_parse_configuration_checks_redirect():
    """
    Check if vhost is vulnerable to misconfigured TLS redirect.
    """

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
            "before": {
                "RewriteEngine": backup_rewrite_engine,
                "RewriteRule": backup_rewrite_rule,
            },
            "after": {
                "RewriteEngine": vhost[RewriteEngine],
                "RewriteRule": vhost[RewriteRule],
            },
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
