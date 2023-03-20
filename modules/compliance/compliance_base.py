import json

from modules.compliance.wrappers.db_reader import Database
from modules.server.wrappers.testssl import Testssl
from utils.loader import load_configuration
from utils.validation import Validator


def convert_signature_algorithm(sig_alg: str) -> str:
    """
    This function is needed to convert the input from testssl to make it compatible with the requirements database
    """
    return sig_alg.replace("-", "_").replace("+", "_").lower()


class ConditionParser:
    def __init__(self):
        self.result = None
        self.expression = ""
        self.logical_separators = ["and", "or"]
        self.instructions = load_configuration("condition_instructions", "configs/compliance/")

    def solve(self):
        pass


class Compliance:
    def __init__(self):
        self._output_file = None
        self._input_dict = {}
        self._database_instance = Database()
        self._last_data = {}
        self._output_dict = {}
        self._user_configuration = {}
        self.evaluations_mapping = load_configuration("evaluations_mapping", "configs/compliance/")
        self.sheet_columns = load_configuration("sheet_columns", "configs/compliance/")
        self.misc_fields = load_configuration("misc_fields", "configs/compliance/")
        self._validator = Validator()
        self.test_ssl = Testssl()

    def evaluation_to_use(self, evaluations, security: bool = True):
        """
        Given two evaluations returns true if the first one wins, false otherwise.

        :param evaluations: list of evaluations to be checked
        :type evaluations: list
        :param security: True if security wins false if legacy wins, default to true
        :type security: bool
        :return: the standard which wins
        :rtype: int
        """
        # If an evaluation is not mapped it can be considered as a Not mentioned
        security_mapping = "security" if security else "legacy"
        if not evaluations:
            raise IndexError("Evaluations list is empty")
        first_value = self.evaluations_mapping.get(security_mapping, {}).get(evaluations[0].replace("°", ""), 4)
        best = 0
        for i, el in enumerate(evaluations[1:]):
            evaluation_value = self.evaluations_mapping.get(security_mapping, {}).get(el.replace("°", ""), 4)
            if first_value > evaluation_value:
                best = i + 1
        # if they have the same value first wins
        return best

    def input(self, **kwargs):
        """
        Set the input parameters

        :param kwargs: input parameters
        :type kwargs: dict

        :Keyword Arguments:
            * *standard* (``list``) -- Guidelines to check against
            * *sheets_to_check* (``dict``) -- of sheets that should be checked in the form: sheet:version_of_protocol
            * *actual_configuration* (``dict``) -- The configuration to check, not needed if generating
            * *test_ssl* (``bool``) -- If true the user_configuration gets generated using testssl data
            * *output_config* (``str``) -- The path and name of the output file
        """
        actual_configuration = kwargs.get("actual_configuration")
        use_test_ssl = kwargs.get("test_ssl")
        output_file = kwargs.get("output_config")
        if actual_configuration and self._validator.dict(actual_configuration):
            self.prepare_configuration(actual_configuration)
        elif use_test_ssl:
            # test_ssl_output = self.test_ssl.run(**{"hostname": "falconvendor.davita.com"})
            # with open("dump.json", "w") as f:
            #     json.dump(test_ssl_output, f, indent=4)

            # this is temporary
            with open("testssl_dump.json", 'r') as f:
                test_ssl_output = json.load(f)
            self.prepare_testssl_output(test_ssl_output)
        elif output_file and self._validator.string(output_file):
            self._output_file = output_file
        self._input_dict = kwargs

    # To override
    def _worker(self, sheets_to_check):
        """
        :param sheets_to_check: dict of sheets that should be checked in the form: sheet:{protocol, version_of_protocol}
        :type sheets_to_check: dict

        :return: processed results
        :rtype: dict

        :raise  NotImplementedError:
        """
        raise NotImplementedError("This method should be reimplemented")

    def run(self, **kwargs):
        self.input(**kwargs)
        sheets_to_check = kwargs.get("sheets_to_check")
        val = Validator()
        val.dict(sheets_to_check)
        self._worker(sheets_to_check)
        return self.output()

    def output(self):
        return self._output_dict.copy()

    def prepare_configuration(self, actual_configuration):
        for field in actual_configuration:
            new_field = actual_configuration[field]
            if isinstance(new_field, str):
                if "Cipher" in field:
                    new_field = new_field.split(":") if ":" in new_field else new_field
                elif "Protocol" in field and " " in new_field:
                    tmp_dict = {}
                    for version in new_field.split(" "):
                        accepted = False if version[0] == '-' else True
                        new_version_name = version.replace("-", "").replace("v", " ")
                        if new_version_name[-2] != '.' and new_version_name != "all":
                            new_version_name += ".0"
                        tmp_dict[new_version_name] = accepted
                    new_field = tmp_dict
            field_name = self._database_instance.configuration_mapping.get(field, field)
            self._user_configuration[field_name] = new_field

    def prepare_testssl_output(self, test_ssl_output):

        for site in test_ssl_output:
            for field in test_ssl_output[site]:
                actual_dict = test_ssl_output[site][field]
                # Each protocol has its own field
                if (field.startswith("SSL") or field.startswith("TLS")) and field[3] != "_":
                    if not self._user_configuration.get("Protocol"):
                        self._user_configuration["Protocol"] = {}
                    protocol_dict = self._user_configuration.get("Protocol")
                    # Standardization to have it compliant with the database
                    new_version_name = field.replace("_", ".").replace("v", " ").replace("TLS1", "TLS 1")
                    if new_version_name[-2] != '.':
                        new_version_name += ".0"
                    # The protocols may appear both as supported and not supported, so they are saved in a dictionary
                    # with a boolean associated to the protocol to know if it is supported or not
                    protocol_dict[new_version_name] = "not" not in actual_dict["finding"]

                # All the ciphers appear in different fields whose form is cipher_%x%
                elif field.startswith("cipher") and "x" in field:
                    if not self._user_configuration.get("CipherSuite"):
                        self._user_configuration["CipherSuite"] = set()
                    value = actual_dict.get("finding", "")
                    if " " in value:
                        # Only the last part of the line is the actual cipher
                        value = value.split(" ")[-1]
                        self._user_configuration["CipherSuite"].add(value)

                elif field.startswith("cert_keySize"):
                    if not self._user_configuration.get("KeyLengths"):
                        self._user_configuration["KeyLengths"] = []
                    # the first two tokens (after doing a space split) are the Algorithm and the keysize
                    self._user_configuration["KeyLengths"].append(actual_dict["finding"].split(" ")[:2])

                elif field == "TLS_extensions":
                    entry = actual_dict["finding"]
                    entry = entry.replace("' '", ",").replace("'", "")
                    extensions: list = entry.split(",")
                    extensions_pairs = {}
                    for ex in extensions:
                        # the [1] is the iana code
                        tokens = ex.split("/#")
                        extensions_pairs[tokens[1]] = tokens[0].lower().replace(" ", "_")
                    self._user_configuration["Extension"] = extensions_pairs

                # From the certificate signature algorithm is possible to extract both CertificateSignature and Hash
                elif field.startswith("cert_Algorithm") or field.startswith("cert_signatureAlgorithm"):
                    if not self._user_configuration.get("CertificateSignature"):
                        self._user_configuration["CertificateSignature"] = set()
                    if not self._user_configuration.get("Hash"):
                        self._user_configuration["Hash"] = set()
                    if " " in actual_dict["finding"]:
                        tokens = actual_dict["finding"].split(" ")
                        sig_alg = tokens[-1]
                        hash_alg = tokens[0]
                        # sometimes the hashing algorithm comes first, so they must be switched
                        if sig_alg.startswith("SHA"):
                            sig_alg, hash_alg = hash_alg, sig_alg
                        self._user_configuration["CertificateSignature"].add(sig_alg)
                        self._user_configuration["Hash"].add(hash_alg)

                # In TLS 1.2 the certificate signatures and hashes are present in the signature algorithms field.
                elif field[-11:] == "12_sig_algs":
                    if not self._user_configuration.get("CertificateSignature"):
                        self._user_configuration["CertificateSignature"] = set()
                    if not self._user_configuration.get("Hash"):
                        self._user_configuration["Hash"] = set()
                    finding = actual_dict["finding"]
                    elements = finding.split(" ") if " " in finding else [finding]
                    hashes = []
                    signatures = []
                    for el in elements:
                        # The ones with the '-' inside are the ones for TLS 1.3.
                        if "-" not in el and "+" in el:
                            # The entries are SigAlg+HashAlg
                            tokens = el.split("+")
                            signatures.append(tokens[0])
                            hashes.append(tokens[1])
                    self._user_configuration["CertificateSignature"].update(signatures)
                    self._user_configuration["Hash"].update(hashes)

                # From TLS 1.3 the signature algorithms are different from the previous versions.
                # So they are saved in a different field of the configuration dictionary.
                elif field[-11:] == "13_sig_algs":
                    if not self._user_configuration.get("Signature"):
                        self._user_configuration["Signature"] = set()
                    finding = actual_dict["finding"]
                    values = finding.split(" ") if " " in finding else [finding]
                    values = [convert_signature_algorithm(sig) for sig in values]
                    self._user_configuration["Signature"].update(values)

                elif field.startswith("cert_keySize"):
                    if not self._user_configuration.get("KeyLengths"):
                        self._user_configuration["KeyLengths"] = set()
                    self._user_configuration["KeyLengths"].update(actual_dict["finding"].split(" ")[:2])

                # The supported groups are available as a list in this field
                elif field[-12:] == "ECDHE_curves":
                    values = actual_dict["finding"].split(" ") if " " in actual_dict["finding"] \
                        else actual_dict["finding"]
                    self._user_configuration["Groups"] = values

                # The transparency field describes how the transparency is handled in each certificate.
                # https://developer.mozilla.org/en-US/docs/Web/Security/Certificate_Transparency (for the possibilities)
                elif "transparency" in field:
                    if not self._user_configuration.get("Transparency"):
                        self._user_configuration["Transparency"] = {}
                    config_dict = self._user_configuration["Transparency"]
                    # the index is basically the certificate number
                    index = len(config_dict)
                    config_dict[index] = actual_dict["finding"]

                elif field in self.misc_fields:
                    if not self._user_configuration.get("Misc"):
                        self._user_configuration["Misc"] = {}
                    self._user_configuration["Misc"][self.misc_fields[field]] = "not" not in actual_dict["finding"]

    def update_result(self, sheet, name, entry_level, is_enabled, source):
        information_level = None
        action = None
        if entry_level == "must" and not is_enabled:
            information_level = "ERROR"
            action = "has to be enabled"
        elif entry_level == "must not" and is_enabled:
            information_level = "ERROR"
            action = "has to be disabled"
        elif entry_level == "recommended" and not is_enabled:
            information_level = "ALERT"
            action = "should be enabled"
        elif entry_level == "not recommended" and is_enabled:
            information_level = "ALERT"
            action = "should be disabled"
        if information_level:
            self._output_dict[sheet][name] = f"{information_level}: {action} according to {source}"

    def is_enabled(self, config_field, name, entry):
        """
        Checks if a field is enabled in the user configuration
        """
        field_value = self._user_configuration[config_field]
        enabled = False
        if isinstance(field_value, dict) and isinstance(field_value.get(name), str):
            # Extensions case
            enabled = name in field_value.items()
        elif isinstance(field_value, dict):
            enabled = field_value.get(name, None)
            if enabled is None:
                enabled = True if "all" in field_value else False
        elif field_value and isinstance(field_value, list) and isinstance(field_value[0], list):
            enabled = entry[:2] in field_value
        elif isinstance(field_value, list) or isinstance(field_value, set):
            enabled = name in field_value
        return enabled
