from ssl import OPENSSL_VERSION


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
        ), "OpenSSL version must be 5 or 6 char long.\nFor example '1.1.1f'"
        assert (
            len(ver2) == 6 or len(ver2) == 5
        ), "OpenSSL version must be 5 or 6 char long.\nFor example '1.1.1f'"
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
