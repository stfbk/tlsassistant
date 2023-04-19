import datetime
import itertools
import json
import re
from pathlib import Path

from modules.compliance.configuration.apache_configuration import ApacheConfiguration
from modules.compliance.configuration.nginx_configuration import NginxConfiguration
from modules.compliance.wrappers.certificateparser import CertificateParser
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
    _logical_separators = ["and", "or"]
    # simple regex to find all occurrences of the separators
    _splitting_regex = "|".join(_logical_separators)
    # same as above but also captures the separators
    _splitting_capturing_regex = "(" + ")|(".join(_logical_separators) + ")"

    def __init__(self, user_configuration):
        self.__logging = Logger("Condition parser")
        self.expression = ""
        self._user_configuration = user_configuration
        self.instructions = load_configuration("condition_instructions", "configs/compliance/")
        self._custom_functions = CustomFunctions(user_configuration)
        self.entry_updates = {}
        self._enabled = None
        self._operators = {
            "and": lambda op1, op2: op1 and op2,
            "or": lambda op1, op2: op1 or op2,
        }

    @staticmethod
    def _partial_match_checker(field_value, name):
        """
        Iters through field_value to check if name is contained in any of them
        :param field_value: iterator to search
        :param name: name to search
        :return: True if the element is contained in the iterator
        :rtype: bool
        """
        enabled = False
        for element in field_value:
            if name in element:
                enabled = True
                break
        return enabled

    @staticmethod
    def is_enabled(user_configuration, config_field, name: str, entry, partial_match=False, condition=""):
        """
        Checks if a field is enabled in the user configuration
        :param user_configuration: the configuration in which the data should be searched
        :param config_field: the field of the configuration containing the target data
        :param name: the value to search
        :param entry: the database entry (only the first two elements are checked, they are needed for KeyLengths)
        :param partial_match: Default to false, if True the
        :param condition: Default to "", the condition that the field has.
        :type condition: str
        :return:
        """
        field_value = user_configuration.get(config_field, None)
        check_first = 0

        if condition:
            conditions = re.split(ConditionParser._splitting_regex, condition, flags=re.IGNORECASE)
            for condition in conditions:
                condition = condition.strip()
                if condition.startswith("CHECK_ONLY_FIRST") and " " in condition:
                    check_first = condition.split(" ")[1]
                    if check_first.isdecimal():
                        check_first = int(check_first)
                    # If the condition value isn't a number it doesn't become an int and the validator gives the error.
                    Validator().int(check_first)

        enabled = False
        if isinstance(field_value, dict) and isinstance(field_value.get(name), bool):
            # Protocols case
            enabled = field_value.get(name, None)
            if enabled is None:
                enabled = True if "all" in field_value else False

        elif isinstance(field_value, dict):
            # Extensions and transparency case
            if name.isnumeric():
                # Iana code case
                enabled = name in field_value
            else:
                enabled = name in field_value.values()
            if not enabled and partial_match:
                enabled = ConditionParser._partial_match_checker(field_value.values(), name)

        elif field_value and isinstance(field_value, set) and isinstance(list(field_value)[0], tuple):
            # KeyLengths case
            enabled = entry[:2] in field_value
            if not enabled and check_first:
                for field in field_value:
                    if field[0] == entry[0] and str(field[1])[:check_first] == str(entry[1])[:check_first]:
                        enabled = True

        elif isinstance(field_value, list) or isinstance(field_value, set):
            enabled = name in field_value
            if not enabled and partial_match:
                enabled = ConditionParser._partial_match_checker(field_value, name)

        return enabled

    @staticmethod
    def _prepare_to_search(field, to_search):
        new_to_search = to_search
        if field == "TLS":
            new_to_search = "TLS " + to_search.strip()
        return new_to_search

    def _closing_parenthesis_index(self, start):
        count = 0
        for i, c in enumerate(self.expression[start:]):
            if c == "(":
                count += 1
            elif c == ")":
                count -= 1
            if count == 0:
                return i + start

    def _solve(self, start, finish):
        to_solve = self.expression[start: finish + 1]

        while "(" in to_solve:
            # So that I'm sure that there aren't any parenthesis in the way
            starting_index = to_solve.index("(") + start
            end_index = self._closing_parenthesis_index(starting_index) - 1
            replacement = self._solve(starting_index + 1, end_index)
            to_replace = self.expression[starting_index:end_index + 2]
            to_solve = to_solve.replace(to_replace, replacement)
        tokens = re.split(self._splitting_regex, to_solve, flags=re.IGNORECASE)
        tokens = [token.strip() for token in tokens]
        for token in tokens:
            to_solve = to_solve.replace(token, str(self._evaluate_condition(token)))
        tokens = re.split(self._splitting_capturing_regex, to_solve, flags=re.IGNORECASE)
        tokens = [token for token in tokens if token]
        while len(tokens) >= 3:
            first_instruction = tokens.pop(0).strip() == "True"
            logical_operation = self._operators[tokens.pop(0).lower()]
            second_instruction = tokens.pop(0).strip() == "True"
            result = logical_operation(first_instruction, second_instruction)
            # After calculating the result it is inserted at the beginning of the tokens list to substitute the three
            # removed elements
            tokens.insert(0, str(result))
        return tokens[0]

    def _evaluate_condition(self, condition):
        """
        Evaluates a condition and returns if it is True or False
        :param condition: condition to evaluate
        :type condition: str
        :return: "True" or "False" accordingly
        :rtype: bool
        """
        negation = False
        if condition[0] == "!":
            condition = condition[1:]
            negation = True
        condition = condition.strip()
        if condition in ["True", "False"]:
            return condition
        if condition not in self.instructions and \
                (" " not in condition and condition.split(" ")[0] not in self.instructions):
            self.__logging.warning(f"Invalid condition: {condition} in expression: {self.expression}. Returning False")
            return "False"
        tokens = condition.split(" ")
        field = tokens[0]
        to_search = self._prepare_to_search(field, tokens[-1])
        config_field = self.instructions.get(field)
        if config_field and config_field.startswith("FUNCTION"):
            assert config_field[8] == " "
            args = {
                "data": to_search,
                "enabled": self._enabled,
                "tokens": tokens[1:]
            }
            result = self._custom_functions.__getattribute__(config_field.split(" ")[1])(**args)
        else:
            # At the moment there is no need to check if a KeyLength is enabled or not, so It is possible to use
            # (None, None)
            enabled = self.is_enabled(self._user_configuration, config_field, to_search, (None, None), True)
            result = enabled if not negation else not enabled
        return result

    def input(self, expression, enabled):
        self.expression = expression
        self._enabled = enabled

    def run(self, expression, enabled):
        if expression:
            self.input(expression, enabled)
        return self.output()

    def output(self):
        solution = self._solve(0, len(self.expression)) == "True"
        self.entry_updates = self._custom_functions.entry_updates.copy()
        self._custom_functions.reset()
        return solution


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
        self._condition_parser = ConditionParser(self._user_configuration)
        self.test_ssl = Testssl()
        self._config_class = None
        self._database_instance.input(["Guideline"])
        self._guidelines = [name[0].upper() for name in self._database_instance.output()]
        self._alias_parser = AliasParser()
        self._certificate_parser = CertificateParser()

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
            * *guidelines_to_check* (``str``) -- string containing the names of the guidelines that should be checked in the form: guideline_version1_version2 in the case of multiple guidelines they should be comma separated
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
        guidelines_string = kwargs.get("guidelines_to_check")
        self._validator.string(guidelines_string)
        guidelines_list = guidelines_string.split(",") if "," in guidelines_string else [guidelines_string]
        sheets_to_check = self._alias_parser.get_sheets_to_check(guidelines_list)
        self._validator.dict(sheets_to_check)
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

    @staticmethod
    def find_cert_index(field: str):
        if "#" in field:
            # the last char is a > so it gets removed
            return field.split("#")[-1].strip(">")
        else:
            return "1"

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
                    if not self._user_configuration.get("CertificateData"):
                        self._user_configuration["CertificateData"] = {}
                    if " " in actual_dict["finding"]:
                        tokens = actual_dict["finding"].split(" ")
                        sig_alg = tokens[-1]
                        hash_alg = tokens[0]
                        # sometimes the hashing algorithm comes first, so they must be switched
                        if sig_alg.startswith("SHA"):
                            sig_alg, hash_alg = hash_alg, sig_alg
                        self._user_configuration["CertificateSignature"].add(sig_alg)
                        self._user_configuration["Hash"].add(hash_alg)
                        cert_index = self.find_cert_index(field)
                        if not self._user_configuration["CertificateData"].get(cert_index):
                            self._user_configuration["CertificateData"][cert_index] = {}
                        self._user_configuration["CertificateData"][cert_index]["SigAlg"] = sig_alg

                elif field.startswith("cert_keySize"):
                    if not self._user_configuration.get("KeyLengths"):
                        self._user_configuration["KeyLengths"] = set()
                    if not self._user_configuration.get("CertificateData"):
                        self._user_configuration["CertificateData"] = {}
                    # the first two tokens (after doing a space split) are the Key Algorithm and its key size
                    element_to_add = actual_dict["finding"].split(" ")[:2]
                    self._user_configuration["KeyLengths"].add(tuple(element_to_add))
                    cert_index = self.find_cert_index(field)
                    if not self._user_configuration["CertificateData"].get(cert_index):
                        self._user_configuration["CertificateData"][cert_index] = {}
                    self._user_configuration["CertificateData"][cert_index]["KeyAlg"] = element_to_add[0]

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

                elif field.startswith("cert_chain_of_trust"):
                    if not self._user_configuration.get("TrustedCerts"):
                        self._user_configuration["TrustedCerts"] = {}
                    config_dict = self._user_configuration["TrustedCerts"]
                    # the index is basically the certificate number
                    index = len(config_dict)
                    config_dict[index] = actual_dict["finding"]

                elif field == "cert" or re.match(r"cert <cert#\d+>", field):
                    if not self._user_configuration.get("CertificateData"):
                        self._user_configuration["CertificateData"] = {}
                    cert_index = self.find_cert_index(field)
                    if not self._user_configuration["CertificateData"].get(cert_index):
                        self._user_configuration["CertificateData"][cert_index] = {}
                    cert_data = self._certificate_parser.run(actual_dict["finding"])
                    for entry in cert_data:
                        self._user_configuration["CertificateData"][cert_index][entry] = cert_data[entry]

                elif field == "intermediate_cert" or re.match(r"intermediate_cert <#\d+>", field):
                    if not self._user_configuration.get("CertificateData"):
                        self._user_configuration["CertificateData"] = {}
                    cert_index = self.find_cert_index(field)
                    cert_index = "int_" + cert_index
                    if not self._user_configuration["CertificateData"].get(cert_index):
                        self._user_configuration["CertificateData"][cert_index] = {}
                    cert_data = self._certificate_parser.run(actual_dict["finding"])
                    for entry in cert_data:
                        self._user_configuration["CertificateData"][cert_index][entry] = cert_data[entry]

                elif field in self.misc_fields:
                    if not self._user_configuration.get("Misc"):
                        self._user_configuration["Misc"] = {}
                    self._user_configuration["Misc"][self.misc_fields[field]] = "not" not in actual_dict["finding"]

    def update_result(self, sheet, name, entry_level, enabled, source, valid_condition):
        information_level = None
        action = None
        entry_level = get_standardized_level(entry_level) if entry_level else None
        if entry_level == "must" and valid_condition and not enabled:
            information_level = "ERROR"
            action = "has to be enabled"
        elif entry_level == "must not" and valid_condition and enabled:
            information_level = "ERROR"
            action = "has to be disabled"
        elif entry_level == "recommended" and valid_condition and not enabled:
            information_level = "ALERT"
            action = "should be enabled"
        elif entry_level == "not recommended" and valid_condition and enabled:
            information_level = "ALERT"
            action = "should be disabled"
        if information_level:
            self._output_dict[sheet][name] = f"{information_level}: {action} according to {source}"
        else:
            self._output_dict[sheet][name] = ""

    def _retrieve_entries(self, sheets_to_check, columns):
        """
        Given the input dictionary and the list of columns updates the entries field with a dictionary in the form
        sheet: data. The data is ordered by name
        """
        entries = {}
        tables = []
        for sheet in sheets_to_check:
            columns_to_get = []
            columns_to_use = self.sheet_columns.get(sheet, {"columns": columns})["columns"]
            if not self._output_dict.get(sheet):
                self._output_dict[sheet] = {}
            for guideline in sheets_to_check[sheet]:
                if guideline.upper() in self._guidelines:
                    table_name = self._database_instance.get_table_name(sheet, guideline,
                                                                        sheets_to_check[sheet][guideline])
                    tables.append(table_name)
            for t in tables:
                for column in columns_to_use:
                    # all the columns are repeated to make easier index access later
                    columns_to_get.append(f"{t}.{column}")

            join_condition = "ON {first_table}.id == {table}.id".format(first_table=tables[0], table="{table}")
            self._database_instance.input(tables, join_condition=join_condition)
            data = self._database_instance.output(columns_to_get)
            entries[sheet] = data
            tables = []
        self.entries = entries

    def _evaluate_entries(self, sheets_to_check, original_columns):
        """
        This function checks the entries with the same name and chooses which guideline to follow for that entry.
        The results can be found in the evaluated_entries field. The dictionary will have form:
        self.evaluated_entries[sheet][count] = {
                        "name": str, The name of the entry
                        "level": str, The level that resulted from the evaluation
                        "source": str, The guideline from which the level is deducted
                        "enabled": bool, If the entry is enabled in the configuration,
                        "valid_condition": bool, If the condition is valid or not
                        "note": str, Eventual note
                    }
        :param sheets_to_check: The input dictionary
        :param columns: columns used to retrieve data from database
        :type columns: list
        """
        # The entry is composed of all the columns repeated n times, with n being the number of guidelines.
        # The step is the number of columns. This allows easy data retrieval by doing something like:
        # "value_index * step * guideline_index" to retrieve data for a specific guideline
        for sheet in self.entries:
            columns = self.sheet_columns.get(sheet, {"columns": original_columns})["columns"]
            guideline_index = columns.index("guidelineName")
            # A more fitting name could be current_requirement_level
            level_index = columns.index("level")
            name_index = columns.index("name")
            condition_index = columns.index("condition")
            # this variable is needed to get the relative position of the condition in respect of the level
            level_to_condition_index = condition_index - level_index
            # this variable is needed to get the relative position of the guideline in respect of the level
            level_to_guideline_index = guideline_index - level_index
            step = len(columns)

            entries = self.entries[sheet]
            if not self.evaluated_entries.get(sheet):
                self.evaluated_entries[sheet] = {}
            custom_guidelines_list = sheets_to_check[sheet].keys() - self._guidelines
            total = 0
            for entry in entries:
                # These three are lists and not a single dictionary because the function level_to_use takes a list
                conditions = []
                levels = []
                # list holding all the notes so that a note gets displayed only if needed
                notes = []
                name = entry[name_index]

                pos = level_index
                field_is_enabled_in_guideline = {}
                while pos < len(entry):
                    level = entry[pos]
                    condition = entry[pos + level_to_condition_index]
                    guideline = entry[pos + level_to_guideline_index]

                    valid_condition = True
                    # Add an empty string to the notes so that all the notes are in the same position of their entry
                    notes.append("")
                    if condition:
                        enabled = self._condition_parser.is_enabled(self._user_configuration, sheet, entry[name_index],
                                                                    entry, condition=condition)
                        valid_condition = self._condition_parser.run(condition, enabled)
                        if self._condition_parser.entry_updates.get("levels"):
                            potential_levels = self._condition_parser.entry_updates.get("levels")
                            level = potential_levels[self.level_to_use(potential_levels)]
                        has_alternative = self._condition_parser.entry_updates.get("has_alternative")
                        additional_notes = self._condition_parser.entry_updates.get("notes", "")
                        if has_alternative and isinstance(condition, str) and condition.count(" ") > 1:
                            parts = condition.split(" ")
                            # Tokens[1] is the logical operator
                            notes[-1] += f"\nNOTE: {name} {parts[1].upper()} {' '.join(parts[2:])} is needed"
                            # This is to trigger the output condition. This works because I'm assuming that "THIS"
                            # is only used in a positive (recommended, must) context.
                            valid_condition = True
                        if additional_notes:
                            notes[-1] += "\nNOTE:"
                            notes[-1] += "\n".join(additional_notes)
                    else:
                        enabled = self._condition_parser.is_enabled(self._user_configuration, sheet, entry[name_index],
                                                                    entry)

                    conditions.append(valid_condition)
                    levels.append(level)
                    field_is_enabled_in_guideline[guideline] = enabled
                    pos += step

                best_level = self.level_to_use(levels)
                resulting_level = levels[best_level]
                condition = conditions[best_level]
                note = notes[best_level]
                # if best level is 0 it is the first one
                source_guideline = entry[guideline_index + step * best_level]

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

                # Custom guidelines don't have notes
                if source_guideline.upper() not in self._guidelines:
                    note = ""

                # Save it to the dictionary
                self.evaluated_entries[sheet][total] = {
                    "entry": entry,
                    "level": resulting_level,
                    "source": source_guideline,
                    "enabled": field_is_enabled_in_guideline[source_guideline],
                    "valid_condition": condition,
                    "note": note
                }
                total += 1


class Generator(Compliance):
    """This class only exists to add fields that are needed by the generator to the Compliance class"""

    def __init__(self):
        super().__init__()
        self._configuration_rules = load_configuration("configuration_rules", "configs/compliance/generate/")
        self._configuration_mapping = load_configuration("configuration_mapping", "configs/compliance/generate/")
        self._user_configuration_types = load_configuration("user_conf_types", "configs/compliance/generate/")
        self._type_converter = {
            "dict": dict,
            "list": list,
            "set": set,
        }

    def _get_config_name(self, field):
        name = self._configuration_mapping.get(field, None)
        if isinstance(name, dict):
            name = list(name.keys())[0]
        return name

    def _fill_user_configuration(self):
        assert self._config_class is not None
        # reset user_configuration to avoid issues
        self._user_configuration = {}
        output_dict = self._config_class.output_dict
        for field in output_dict:
            config_field = self._get_config_name(field)
            save_in = self._user_configuration_types.get(config_field)
            save_in = self._type_converter.get(save_in)
            current_field = output_dict[field]
            if config_field and save_in:
                if self._user_configuration.get(config_field) is None:
                    self._user_configuration[config_field] = save_in()
                user_conf_field = self._user_configuration[config_field]
                if isinstance(user_conf_field, list):
                    values = [val for val in current_field if current_field[val]["added"]]
                    user_conf_field.extend(values)
                elif isinstance(user_conf_field, set):
                    values = [val for val in current_field if current_field[val]["added"]]
                    user_conf_field.update(values)
                elif isinstance(user_conf_field, dict):
                    for val in current_field:
                        if config_field == "Protocol":
                            user_conf_field[val] = current_field[val]["added"]
                        elif config_field == "Extension":
                            self._database_instance.input(["Extension"], other_filter=f'WHERE name=="{val}"')
                            iana_code = self._database_instance.output(["iana_code"])[0][0]
                            user_conf_field[str(iana_code)] = val

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

    def _check_conditions(self):
        """
        Checks the conditions and removes/adds fields if needed
        """
        conditions_to_check = self._config_class.conditions_to_check
        for index in conditions_to_check:
            expression = conditions_to_check[index]["expression"]
            level = get_standardized_level(conditions_to_check[index]["level"])
            data = conditions_to_check[index]["data"]
            columns = conditions_to_check[index]["columns"]
            guideline = conditions_to_check[index]["guideline"]
            field = conditions_to_check[index]["field"]
            enabled = level in ["recommended", "must"]
            valid_condition = self._condition_parser.run(expression, enabled)
            field_rules = self._configuration_rules.get(field, {})

            if self._condition_parser.entry_updates.get("levels"):
                potential_levels = self._condition_parser.entry_updates.get("levels")
                level = potential_levels[self.level_to_use(potential_levels)]
            if not valid_condition and enabled:
                self._config_class.remove_field(field)
            elif level in ["not recommended", "must not"] and valid_condition:
                self._config_class.remove_field(field)
            elif enabled and valid_condition:
                self._config_class.add_configuration_for_field(field, field_rules, data, columns, guideline)

    def output(self):
        self._fill_user_configuration()
        self._check_conditions()
        return self._config_class.configuration_output()


class CustomFunctions:
    def __init__(self, user_configuration):
        self._user_configuration = user_configuration
        self._validator = Validator()
        self._entry_updates = {"levels": [], "notes": []}
        self._operators = {
            ">": lambda op1, op2: op1 > op2,
            "<": lambda op1, op2: op1 < op2,
            ">=": lambda op1, op2: op1 >= op2,
            "<=": lambda op1, op2: op1 <= op2,
            "==": lambda op1, op2: op1 == op2
        }

    # INSERT ALL THE CUSTOM PARSING FUNCTIONS HERE THEY MUST HAVE SIGNATURE:
    # function(**kwargs) -> bool

    def check_year(self, **kwargs):
        """
        :param kwargs: Dictionary of arguments
        :type kwargs: dict
        :return: True if the year indicated has already passed
        :rtype: bool
        :Keyword Arguments:
            * *data* (``str``) -- Year to check
        """
        year = kwargs.get("data", None)
        if not year:
            raise ValueError("No year provided")
        self._validator.string(year)
        # This means that the guideline document didn't define a limit to this condition
        if year[-1] == "+":
            return True

        actual_date = datetime.date.today()
        parsed_date = datetime.datetime.strptime(year + "-12-31", "%Y-%m-%d")
        return parsed_date.date() > actual_date

    def check_vlp(self, **kwargs):
        status = kwargs.get("data", "").lower() == "true"
        result = False
        for version in range(3):
            enabled = ConditionParser.is_enabled(self._user_configuration, "Protocol", f"TLS 1.{version}", (None, None))
            if enabled and not status:
                result = True
                self._entry_updates["levels"].append("must not")
        # This final operation should give True only if both status and result are True or both are False
        return (result and status) or not (result or status)

    def check_ca(self, **kwargs):
        to_check = kwargs.get("data", None)
        if not to_check:
            raise ValueError("No year provided")
        self._validator.string(to_check)
        if " " in to_check:
            tokens = to_check.split(" ")
            if tokens[0] == "count":
                count = self._count_ca()
                op = tokens[1]
                num = tokens[2]
                self._validator.int(num)
                return self._operators[op](count, num)
            elif tokens[0] == "publicly":
                certs_trust_dict = self._user_configuration.get("TrustedCerts", {})
                trusted = True
                if not certs_trust_dict:
                    trusted = False
                for cert in certs_trust_dict:
                    if certs_trust_dict[cert] != "passed.":
                        trusted = False
                return trusted

    def _count_ca(self):
        cas = set()
        for field in self._user_configuration:
            if field.startswith("cert_caIssuers"):
                cas.add(self._user_configuration[field]["finding"])
        return len(cas)

    def check_this(self, **kwargs):
        """
            :param kwargs: Dictionary of arguments
            :type kwargs: dict
            :return: True if either the one calling or the other is enabled
            :rtype: bool
            :Keyword Arguments:
                * *enabled* (``bool``) -- Whether the entry with this condition is enabled or not
        """
        enabled = kwargs.get("enabled", False)
        self._entry_updates["has_alternative"] = True
        return enabled

    def add_notes(self, **kwargs):
        note = " ".join(kwargs.get("tokens", []))
        self._entry_updates["notes"].append(note)
        return True

    def check_key_type(self, **kwargs):
        """
            :param kwargs: Dictionary of arguments
            :type kwargs: dict
            :return: True always
            :rtype: bool
            :Keyword Arguments:
                * *data* (``str``) -- The name of the algorithm that is using the condition
        """
        note = ""
        alg = kwargs.get("data", "").lower()
        valid_pairs = [["ECDSA", "ECDH"], ["DSA", "DH"]]
        recommend_dsa = False
        for cert in self._user_configuration["CertificateData"]:
            cert_data = self._user_configuration["CertificateData"][cert]
            data_pair = [cert_data["SigAlg"], cert_data["KeyAlg"]]
            if cert_data["KeyAlg"] == "DH":
                recommend_dsa = True
            if data_pair[0].lower() == alg and data_pair[0] != data_pair[1] and data_pair not in valid_pairs:
                note = f"The certificate with index {cert} isn't compliant with the guideline because it is signed " \
                       f"with an algorithm that isn't consistent with the public key"
        if note:
            self._entry_updates["notes"].append(note)
        if recommend_dsa:
            self._entry_updates["levels"].append("recommended")
        return True

    @staticmethod
    def always_true(**kwargs):
        return True

    @property
    def entry_updates(self):
        return self._entry_updates

    def reset(self):
        self._entry_updates = {"levels": [], "notes": []}


class AliasParser:
    def __init__(self):
        self.__logging = Logger("Compliance module")
        self._database_instance = Database()
        self._guidelines = [name[0].upper() for name in self._database_instance.run(["Guideline"])]
        # simple regex to find and capture all occurrences of the guidelines
        self._splitting_regex = "(" + ")|(".join(self._guidelines) + ")"
        self._sheets_versions_dict = {}
        self._fill_sheets_dict()
        self._guidelines_versions = {}
        self._fill_guidelines_versions()
        self._aliases = load_configuration("alias_mapping", "configs/compliance/alias/")
        self._default_versions = load_configuration("default_versions", "configs/compliance/alias/")

    def list_aliases(self):
        print("Alias mapping:")
        for el in self._aliases:
            print(el, ":", self._aliases[el])
        import sys
        sys.exit(0)

    def list_strings(self):
        print("Valid strings:")
        for guideline in self._guidelines_versions:
            sets = [self._guidelines_versions[guideline][k] for k in self._guidelines_versions[guideline]]
            # this first list comprehension is needed to later check if there are any versions.
            combinations = [combination for combination in itertools.product(*sets)]
            if combinations and combinations[0]:
                print("Strings for guideline: ", guideline)
                # First I join the output from itertools.product using "_" then I prepend guideline_ to it and in the
                # end I join all the versions using ","
                result = ",".join([guideline + "_" + "_".join(combination) for combination in combinations])
                print(result)
            else:
                print("Guideline ", guideline, " doesn't have any special version")
            print("")
        print("NOTE: if a version is omitted the default one will be used.")

    def _fill_sheets_dict(self):
        for table in self._database_instance.table_names:
            tokens = re.split(self._splitting_regex, table, flags=re.IGNORECASE)
            tokens = [t for t in tokens if t]
            # If the length is one or less the table is a general data table.
            if len(tokens) > 1:
                sheet = tokens[0]
                guideline = tokens[1]
                version = tokens[2] if len(tokens) == 3 else ""
                if self._sheets_versions_dict.get(sheet) is None:
                    self._sheets_versions_dict[sheet] = {guideline: set()}
                if self._sheets_versions_dict[sheet].get(guideline) is None:
                    self._sheets_versions_dict[sheet][guideline] = set()
                self._sheets_versions_dict[sheet][guideline].add(version)

    def _fill_guidelines_versions(self):
        for i, sheet in enumerate(self._sheets_versions_dict):
            for guideline in self._sheets_versions_dict[sheet]:
                if self._guidelines_versions.get(guideline) is None:
                    self._guidelines_versions[guideline] = {}
                guideline_dict = self._guidelines_versions[guideline]
                for version in self._sheets_versions_dict[sheet][guideline]:
                    new_set = True
                    for index in guideline_dict:
                        if version.upper() in guideline_dict[index]:
                            new_set = False
                    if new_set and version:
                        if guideline_dict.get(i) is None:
                            guideline_dict[i] = set()
                        guideline_dict[i].add(version.upper())

    def is_valid(self, alias):
        if "_" not in alias and alias.upper() not in self._guidelines:
            raise ValueError(f"Alias {alias} not valid")
        tokens = alias.split("_")
        guideline = tokens[0].upper()
        if guideline not in self._guidelines_versions:
            raise ValueError(f"Invalid guideline in alias: {alias}")
        used_sets = set()
        for token in tokens[1:]:
            found = False
            for index in self._guidelines_versions[guideline]:
                # If it is an abbreviation get the complete name.
                token = self._aliases.get(token.upper(), token.upper())
                if token in self._guidelines_versions[guideline][index] and index not in used_sets:
                    found = True
                    used_sets.add(index)
            if not found:
                raise ValueError(f"Invalid version {token} for alias: {alias}")

    def get_sheets_to_check(self, aliases):
        sheets_to_check = {}
        for alias in aliases:
            alias = alias.strip()
            self.is_valid(alias)
            tokens = alias.split("_")
            guideline = tokens[0].upper()
            tokens.append("")
            for i, sheet in enumerate(self._sheets_versions_dict):
                if sheets_to_check.get(sheet) is None:
                    sheets_to_check[sheet] = {}
                for token in tokens[1:]:
                    token = token.upper()
                    # If it is an abbreviation get the complete name.
                    token = self._aliases.get(token, token)
                    if sheet + guideline + token in self._database_instance.table_names:
                        sheets_to_check[sheet][guideline] = token
                if sheets_to_check[sheet].get(guideline) is None:
                    version = self._default_versions[sheet].get(guideline)
                    if version is not None:
                        sheets_to_check[sheet][guideline] = version
                    else:
                        self.__logging.info(f"Skipping {guideline} in {sheet} because no version is available.")
        return sheets_to_check
