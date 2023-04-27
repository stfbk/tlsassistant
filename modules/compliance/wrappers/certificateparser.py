import OpenSSL.crypto as crypto
from dateutil import parser


class CertificateParser:
    def __init__(self):
        self.certificate = None
        self._output_dict = {}

    def input(self, certificate):
        self.certificate = crypto.load_certificate(crypto.FILETYPE_PEM, certificate)

    def run(self, certificate):
        self.input(certificate)
        cert_sha = self.certificate.digest("SHA256").decode("utf-8")
        self._output_dict[cert_sha] = {
            "Extensions": {}
        }
        if not isinstance(self.certificate, crypto.X509):
            return {}
        for index in range(self.certificate.get_extension_count()):
            ext = self.certificate.get_extension(index)
            ext_name = ext.get_short_name().decode("utf-8")
            self._output_dict[cert_sha]["Extensions"][ext_name] = ext.__str__()
        self._output_dict[cert_sha]["X.509 version"] = self.certificate.get_version()
        self._output_dict[cert_sha]["SigAlgComplete"] = self.certificate.get_signature_algorithm().decode("utf-8")
        # this list comprehension takes every tuple, decodes its elements and puts the decoded pair in a new list
        entries = [[el.decode("utf-8") for el in entry] for entry in self.certificate.get_issuer().get_components()]
        self._output_dict[cert_sha]["Issuer Distinguished Name"] = dict(entries)
        entries = [[el.decode("utf-8") for el in entry] for entry in self.certificate.get_subject().get_components()]
        self._output_dict[cert_sha]["Subject Distinguished Name"] = dict(entries)
        # validity should be the difference between these two fields
        not_after = self.certificate.get_notAfter().decode("utf-8")
        not_before = self.certificate.get_notBefore().decode("utf-8")
        self._output_dict[cert_sha]["not_after"] = not_after
        self._output_dict[cert_sha]["not_before"] = not_before
        self._output_dict[cert_sha]["validity"] = parser.parse(not_after) - parser.parse(not_before)
        return self.output(cert_sha)

    def output(self, cert_sha):
        return self._output_dict.get(cert_sha, {}).copy()
