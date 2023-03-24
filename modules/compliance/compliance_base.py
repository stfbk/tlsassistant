import json
from pathlib import Path

from modules.compliance.configuration.apache_configuration import ApacheConfiguration
from modules.compliance.configuration.nginx_configuration import NginxConfiguration
from modules.compliance.wrappers.db_reader import Database
from modules.server.wrappers.testssl import Testssl
from utils.database import get_standardized_level
from utils.loader import load_configuration
from utils.logger import Logger
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
        self._custom_guidelines = None
        self._apache = True
        self._input_dict = {}
        self._database_instance = Database()
        self.__logging = Logger("Compliance module")
        self._last_data = {}
        self._output_dict = {}
        self._user_configuration = {}
        self.entries = {}
        self.evaluated_entries = {}
        self.evaluations_mapping = load_configuration("evaluations_mapping", "configs/compliance/")
        self.sheet_columns = load_configuration("sheet_columns", "configs/compliance/")
        self.misc_fields = load_configuration("misc_fields", "configs/compliance/")
        self._validator = Validator()

        # This will be removed when integrating the module in the core
        self.test_ssl = Testssl()

        self._config_class = None
        self._database_instance.input(["Guideline"])
        self._guidelines = [name[0].upper() for name in self._database_instance.output()]

    def level_to_use(self, levels, security: bool = True):
        """
        Given two evaluations returns true if the first one wins, false otherwise.

        :param levels: list of evaluations to be checked
        :type levels: list
        :param security: True if security wins false if legacy wins, default to true
        :type security: bool
        :return: the standard which wins
        :rtype: int
        """
        # If a level is not mapped it can be considered as a Not mentioned
        security_mapping = "security" if security else "legacy"
        if not levels:
            raise IndexError("Levels list is empty")
        first_value = self.evaluations_mapping.get(security_mapping, {}).get(get_standardized_level(levels[0]), 4)
        best = 0
        for i, el in enumerate(levels[1:]):
            evaluation_value = self.evaluations_mapping.get(security_mapping, {}).get(get_standardized_level(el), 4)
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
            * *sheets_to_check* (``dict``) -- dictionary of sheets that should be checked in the form: sheet:version_of_protocol
            * *actual_configuration_path* (``str``) -- The configuration to check, not needed if generating
            * *hostname* (``str``) -- Hostname on which testssl should be used
            * *apache* (``bool``) -- Default to True, if false nginx will be used
            * *config_output* (``str``) -- The path and name of the output file
            * *custom_guidelines* (``dict``) -- dictionary with form: { sheet : {guideline: name: {"level":level}}
        """
        actual_configuration = kwargs.get("actual_configuration_path")
        hostname = kwargs.get("hostname")
        self._apache = kwargs.get("apache", True)
        output_file = kwargs.get("output_config")
        self._custom_guidelines = kwargs.get("custom_guidelines")
        if actual_configuration and self._validator.string(actual_configuration):
            try:
                self._config_class = ApacheConfiguration(actual_configuration)
            except Exception as e:
                self.__logging.debug(
                    f"Couldn't parse config as apache: {e}\ntrying with nginx..."
                )
                self._config_class = NginxConfiguration(actual_configuration)
            self.prepare_configuration(self._config_class.configuration)
        if hostname and self._validator.string(hostname):
            # test_ssl_output = self.test_ssl.run(**{"hostname": hostname})

            # this is temporary
            with open("testssl_dump.json", 'r') as f:
                test_ssl_output = json.load(f)
            self.prepare_testssl_output(test_ssl_output)
        if output_file and self._validator.string(output_file):
            if self._apache:
                self._config_class = ApacheConfiguration()
            else:
                self._config_class = NginxConfiguration()
            self._config_class.set_out_file(Path(output_file))
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
            field_name = self._config_class.reverse_mapping.get(field, field)
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
        entry_level = get_standardized_level(entry_level)
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
        if isinstance(field_value, dict) and isinstance(field_value.get(name), bool):
            # Protocols case
            enabled = field_value.get(name, None)
            if enabled is None:
                enabled = True if "all" in field_value else False
        elif isinstance(field_value, dict):
            # Extensions case
            enabled = name in field_value.values()
        elif field_value and isinstance(field_value, list) and isinstance(field_value[0], list):
            enabled = entry[:2] in field_value
        elif isinstance(field_value, list) or isinstance(field_value, set):
            enabled = name in field_value
        return enabled

    def _retrieve_entries(self, sheets_to_check, columns):
        """
        Given the input dictionary and the list of columns updates the entries field with a dictionary in the form
        sheet: data. The data is ordered by name
        """
        entries = {}
        tables = []
        for sheet in sheets_to_check:
            if not self._output_dict.get(sheet):
                self._output_dict[sheet] = {}
            for guideline in sheets_to_check[sheet]:
                if guideline.upper() in self._guidelines:
                    table_name = self._database_instance.get_table_name(sheet, guideline,
                                                                        sheets_to_check[sheet][guideline])
                    tables.append(table_name)
            self._database_instance.input(tables, other_filter="ORDER BY name")
            data = self._database_instance.output(columns)
            entries[sheet] = data
            tables = []
        self.entries = entries

    def _evaluate_entries(self, sheets_to_check, columns):
        """
        This function checks the entries with the same name and chooses which guideline to follow for that entry.
        The results can be found in the evaluated_entries field. The dictionary will have form:
        self.evaluated_entries[sheet][count] = {
                        "name": str, The name of the entry
                        "level": str, The level that resulted from the evaluation
                        "source": str The guideline from which the level is deducted
                    }
        :param sheets_to_check: The input dictionary
        :param columns: columns used to retrieve data from database
        :type columns: list
        """
        # A more fitting name could be current_requirement_level
        resulting_level = "<Not mentioned>"
        guideline_index = columns.index("guidelineName")
        level_index = columns.index("level")
        name_index = columns.index("name")
        for sheet in self.entries:
            # The total value is used as an index to avoid eventual collisions between equal names in the same sheet
            total = 0
            if not self.evaluated_entries.get(sheet):
                self.evaluated_entries[sheet] = {}
            counter = 1
            source_guideline = self.entries[sheet][guideline_index]
            for entry in self.entries[sheet]:
                entry_level = entry[level_index]
                guideline = entry[guideline_index]
                if entry_level != resulting_level:
                    levels = [resulting_level, entry_level]
                    best_level = self.level_to_use(levels)
                    # if best_level is 0 the source_guideline is the same
                    if best_level:
                        source_guideline = guideline
                    resulting_level = levels[best_level]
                # The entries are ordered by name so every time the counter is the same as the number of guidelines to
                # check it is time to add the entry to the output dictionary.
                custom_guidelines_list = sheets_to_check[sheet].keys() - self._guidelines
                if sheet and counter == len(sheets_to_check[sheet]) - len(custom_guidelines_list):
                    counter = 0
                    name = entry[name_index]
                    for guideline in custom_guidelines_list:
                        custom_entry = self._custom_guidelines[sheet][guideline].get(name)
                        if custom_entry:
                            levels = [resulting_level, custom_entry["level"]]
                            guidelines_to_check = list(sheets_to_check[sheet])
                            # If the custom_guideline appears before the source_guideline (actual guideline from which
                            # the level was deducted) it has greater priority, so it is necessary to switch them
                            if guidelines_to_check.index(guideline) < guidelines_to_check.index(source_guideline):
                                levels = levels[::-1]
                            best_level = self.level_to_use(levels)
                            # if best_level is 0 the source_guideline is the best
                            if best_level:
                                source_guideline = guideline
                            resulting_level = levels[best_level]

                    # Save it to the dictionary
                    self.evaluated_entries[sheet][total] = {
                        "entry": entry,
                        "level": resulting_level,
                        "source": source_guideline
                    }
                    # the resulting level is reset so that it doesn't influence the next element.
                    resulting_level = "<Not mentioned>"
                    total += 1
                counter += 1


class Generator(Compliance):
    """This class only exists to add fields that are needed by the generator to the Compliance class"""

    def __init__(self):
        super().__init__()
        self._configuration_rules = load_configuration("configuration_rules", "configs/compliance/generate/")
        self._configuration_mapping = load_configuration("configuration_mapping", "configs/compliance/generate/")

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

    def output(self):
        return self._config_class.configuration_output()
