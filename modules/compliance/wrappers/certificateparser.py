from cryptography import x509
from cryptography.hazmat.primitives import hashes
from dateutil import parser
from pyasn1.codec.der.decoder import decode as der_decoder


class CertificateParser:
    def __init__(self):
        self.certificate = None
        self._output_dict = {}

    def input(self, certificate):
        self.certificate = x509.load_pem_x509_certificate(certificate.encode())

    def run(self, certificate):
        self.input(certificate)
        cert_sha = self.certificate.fingerprint(hashes.SHA256()).hex()
        self._output_dict[cert_sha] = {
            "Extensions": {}
        }
        if not isinstance(self.certificate, x509.Certificate):
            return {}
        for ext in self.certificate.extensions:
            ext_name = ext.oid._name.replace("cRLDistributionPoints", "crlDistributionPoints")
            content = ext.value
            self._output_dict[cert_sha]["Extensions"][ext_name] = content
        self._output_dict[cert_sha]["X.509 version"] = self.certificate.version.value
        self._output_dict[cert_sha]["SigAlgName"] = self.certificate.signature_algorithm_oid._name
        self._output_dict[cert_sha]["SigAlgOID"] = self.certificate.signature_algorithm_oid.dotted_string
        self._output_dict[cert_sha]["KeySize"] = self.certificate.public_key().key_size
        # this list comprehension takes every tuple, decodes its elements and puts the decoded pair in a new list
        if self.certificate.issuer:
            issuer_der = der_decoder(self.certificate.issuer.public_bytes())[0]
            issuer_string = self.certificate.issuer.rfc4514_string()
            issuer_string = issuer_string.replace("\,", "COMMA")
            components = issuer_string.split(",") if "," in issuer_string else [issuer_string]
            entries = [entry.split("=") for entry in components]
            entries = [(entry[0], entry[1].replace("COMMA", ",")) for entry in entries]
        self._output_dict[cert_sha]["Issuer Distinguished Name - der"] = issuer_der
        self._output_dict[cert_sha]["Issuer Distinguished Name"] = dict(entries)
        if self.certificate.subject:
            subject_der = der_decoder(self.certificate.subject.public_bytes())[0]
            subject_der = der_decoder(self.certificate.subject.public_bytes())[0]
            subject_string = self.certificate.subject.rfc4514_string()
            components = subject_string.split(",") if "," in subject_string else [subject_string]
            entries = [entry.split("=") for entry in components]
        self._output_dict[cert_sha]["Subject Distinguished Name - der"] = subject_der
        # validity should be the difference between these two fields
        not_after = self.certificate.not_valid_after_utc
        not_before = self.certificate.not_valid_before_utc
        self._output_dict[cert_sha]["not_after"] = not_after
        self._output_dict[cert_sha]["not_before"] = not_before
        self._output_dict[cert_sha]["validity"] = not_after - not_before
        return self.output(cert_sha)

    def output(self, cert_sha):
        return self._output_dict.get(cert_sha, {}).copy()
