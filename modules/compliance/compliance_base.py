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


class Compliance:
    def __init__(self):
        self._input_dict = {}
        self._database_instance = Database()
        self._last_data = {}
        self._output_dict = {}
        self._user_configuration = {}
        self.evaluations_mapping = load_configuration("evaluations_mapping", "configs/modules/compliance/")
        self.sheet_columns = load_configuration("sheet_columns", "configs/modules/compliance/")
        self.misc_fields = load_configuration("misc_fields", "configs/modules/compliance/")
        self.test_ssl = Testssl()

    def evaluation_to_use(self, evaluations, security: bool = True):
        """
        Given two evaluations returns true if the first one wins, false otherwise.

        :param evaluations: list of evaluations to be checked
        :type evaluations: list
        :param security: True if security wins false if legacy wins, default to true
        :type security: bool
        :return: the standard which wins
        :rtype: bool
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
        """
        actual_configuration = kwargs.get("actual_configuration")
        use_test_ssl = kwargs.get("test_ssl")
        if actual_configuration and Validator([(actual_configuration, dict)]):
            self.prepare_configuration(actual_configuration)
        elif use_test_ssl:
            # test_ssl_output = self.test_ssl.run(**{"hostname": "falconvendor.davita.com"})
            # with open("dump.json", "w") as f:
            #     json.dump(test_ssl_output, f, indent=4)

            # this is temporary
            with open("testssl_dump.json", 'r') as f:
                test_ssl_output = json.load(f)
            self.prepare_testssl_output(test_ssl_output)

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
                if (field.startswith("SSL") or field.startswith("TLS")) and field[3] != "_":
                    if not self._user_configuration.get("Protocol"):
                        self._user_configuration["Protocol"] = {}
                    protocol_dict = self._user_configuration.get("Protocol")
                    new_version_name = field.replace("_", ".").replace("v", " ").replace("TLS1", "TLS 1")
                    if new_version_name[-2] != '.':
                        new_version_name += ".0"
                    protocol_dict[new_version_name] = "not" not in actual_dict["finding"]
                elif field.startswith("cipher") and "x" in field:
                    if not self._user_configuration.get("CipherSuite"):
                        self._user_configuration["CipherSuite"] = set()
                    value = actual_dict.get("finding", "")
                    if " " in value:
                        value = value.split(" ")[-1]
                        self._user_configuration["CipherSuite"].add(value)
                elif field.startswith("cert_keySize"):
                    if not self._user_configuration.get("KeyLengths"):
                        self._user_configuration["KeyLengths"] = []
                    self._user_configuration["KeyLengths"].append(actual_dict["finding"].split(" ")[:2])
                elif field == "TLS_extensions":
                    entry = actual_dict["finding"]
                    entry = entry.replace("' '", ",").replace("'", "")
                    extensions: list = entry.split(",")
                    extensions_pairs = []
                    for ex in extensions:
                        # the [1] is the iana code
                        extensions_pairs.append(ex.split("/#")[0].lower().replace(" ", "_"))
                    self._user_configuration["Extension"] = extensions_pairs
                elif field.startswith("cert_Algorithm") or field.startswith("cert_signatureAlgorithm"):
                    if not self._user_configuration.get("CertificateSignature"):
                        self._user_configuration["CertificateSignature"] = set()
                    if not self._user_configuration.get("Hash"):
                        self._user_configuration["Hash"] = set()
                    if " " in actual_dict["finding"]:
                        tokens = actual_dict["finding"].split(" ")
                        sig_alg = tokens[-1]
                        hash_alg = tokens[0]
                        if sig_alg.startswith("SHA"):
                            sig_alg, hash_alg = hash_alg, sig_alg
                        self._user_configuration["CertificateSignature"].add(sig_alg)
                        self._user_configuration["Hash"].add(hash_alg)
                # TODO discuss this during the meeting
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
                        if "-" not in el and "+" in el:
                            tokens = el.split("+")
                            signatures.append(tokens[0])
                            hashes.append(tokens[1])
                    self._user_configuration["CertificateSignature"].update(signatures)
                    self._user_configuration["Hash"].update(hashes)
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
                elif field[-12:] == "ECDHE_curves":
                    values = actual_dict["finding"].split(" ") if " " in actual_dict["finding"] \
                        else actual_dict["finding"]
                    self._user_configuration["Groups"] = values

                elif field in self.misc_fields:
                    if not self._user_configuration.get("Misc"):
                        self._user_configuration["Misc"] = {}
                    self._user_configuration["Misc"][self.misc_fields[field]] = "not" not in actual_dict["finding"]

    def update_result(self, sheet, name, evaluation, is_enabled):
        information_level = None
        action = None
        if evaluation == "must" and not is_enabled:
            information_level = "ERROR"
            action = "has to be enabled"
        elif evaluation == "must not" and is_enabled:
            information_level = "ERROR"
            action = "has to be disabled"
        elif evaluation == "recommended" and not is_enabled:
            information_level = "ALERT"
            action = "should be enabled"
        elif evaluation == "not recommended" and is_enabled:
            information_level = "ALERT"
            action = "should be disabled"
        if information_level:
            self._output_dict[sheet][name] = f"{information_level}: {name} {action}"

    def is_enabled(self, config_field, name, entry):
        """
        Checks if a field is enabled in the user configuration
        """
        field_value = self._user_configuration[config_field]
        enabled = False
        if isinstance(field_value, dict):
            enabled = field_value.get(name, None)
            if enabled is None:
                enabled = True if "all" in field_value else False
        elif field_value and isinstance(field_value, list) and isinstance(field_value[0], list):
            enabled = entry[:2] in field_value
        elif isinstance(field_value, list) or isinstance(field_value, set):
            enabled = name in field_value
        return enabled
