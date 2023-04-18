import OpenSSL.crypto as crypto


class CertificateParser:
    def __init__(self):
        self.certificate = ""
        self._output_dict = {}

    def input(self, certificate):
        self.certificate = certificate

    def run(self, certificate):
        loaded_cert = crypto.load_certificate(crypto.FILETYPE_PEM, certificate)
        cert_sha = loaded_cert.digest("SHA256").decode("utf-8")
        self._output_dict[cert_sha] = {
            "extensions": {}
        }
        for index in range(loaded_cert.get_extension_count()):
            ext = loaded_cert.get_extension(index)
            ext_name = ext.get_short_name().decode("utf-8")
            self._output_dict[cert_sha]["extensions"][ext_name] = ext.__str__()

        return self.output(cert_sha)

    def output(self, cert_sha):
        return self._output_dict.get(cert_sha, {}).copy()
