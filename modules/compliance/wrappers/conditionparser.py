import datetime
import re

from pyasn1.type.char import PrintableString
from pyasn1.type.univ import SequenceOf

from cryptography import x509

from modules.compliance.wrappers.db_reader import Database

from utils.loader import load_configuration
from utils.logger import Logger
from utils.validation import Validator

# Configs from the tls-compliance-dataset repository
from configs import sheets_mapping, has_numeric_id


class ConditionParser:
    _instructions = load_configuration(
        "condition_instructions", "configs/compliance/")
    _instructions_keys = '|'.join(_instructions.keys())
    _no_match = "calculated"
    _logical_separators = [" and ", " or ", " xor "]
    # this string ensures that the logical_separators are only matched if they are followed by a valid instruction
    _concatenation_string = f"(?!{_no_match})(?={_instructions_keys}|True|False|!)"
    regex_separators = []
    for el in _logical_separators:
        regex_separators.append(el + _concatenation_string)
    # simple regex to find all occurrences of the separators
    _splitting_regex = "|".join(regex_separators)
    # same as above but also captures the separators
    splitting_capturing_regex = "(" + ")|(".join(regex_separators) + ")"
    _sheet_mapping = sheets_mapping
    _has_numeric_id = has_numeric_id
    _additional_info = {}
    _additional_info_columns = {
        "Signature": ["id", "version"]
    }
    _database_instance = Database()
    for sheet in _additional_info_columns:
        if _additional_info.get(sheet) is None:
            _additional_info[sheet] = {}
            columns = _additional_info_columns.get(sheet, [])
            results = _database_instance.run(
                tables=[sheet], columns=columns)
            # make results a dictionary with the first column as key
            # and the rest as values
            results = {row[0]: row[1:] for row in results}
            _additional_info[sheet] = results
    __logging = Logger("Condition parser")
    __logging.debug(_splitting_regex)

    general_name_dictionary = {
        "IP": x509.IPAddress,
        "DNS": x509.DNSName,
        "DIRECTORY": x509.DirectoryName,
        "URI": x509.UniformResourceIdentifier,
        "ID": x509.RegisteredID,
        "OTHER": x509.OtherName
    }

    # mapping from field indicator used in the conditions to the field of the configuration dictionary

    def __init__(self, user_configuration):
        self.expression = ""
        self._user_configuration = user_configuration
        self._custom_functions = CustomFunctions(user_configuration)
        self.entry_updates = {}
        self._enabled = None
        self._operators = {
            "and": lambda op1, op2: op1 and op2,
            "or": lambda op1, op2: op1 or op2,
            "xor": lambda op1, op2: (not op1) != (not op2),
        }
        self._certificate_index = "1"

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
    def is_enabled(user_configuration, config_field, name: str, entry, partial_match=False, condition="",
                   certificate_index="1"):
        """
        Checks if a field is enabled in the user configuration
        :param user_configuration: the configuration in which the data should be searched
        :param config_field: the field of the configuration containing the target data
        :param name: the value to search
        :param entry: the database entry (only the first two elements are checked, they are needed for KeyLengths)
        :param partial_match: Default to false, if True the
        :param condition: Default to "", the condition that the field has.
        :type condition: str
        :param certificate_index: Default to "1", the certificate to check
        :type certificate_index: str
        :return:
        """
        check_first = None
        if condition:
            check_first = ConditionParser.get_check_first(condition)

        enabled = False
        if config_field in ConditionParser._has_numeric_id and isinstance(entry[0], int):
            if entry[0] in ConditionParser._additional_info.get(config_field, []):
                additional_data = ConditionParser._additional_info.get(
                    config_field, {}).get(entry[0], [])
                # Signature case
                if additional_data[0] and len(additional_data) == 1:
                    additional_data = additional_data[0].replace(".", "")
                    config_field = config_field + "_" + additional_data
        field_value = user_configuration.get(config_field, {})

        if isinstance(field_value, dict) and isinstance(field_value.get(name), bool):
            # Protocols case
            enabled = field_value.get(name, None)
            if enabled is None:
                enabled = True if "all" in field_value else False

        # the extensions are saved using their IANA id as key in the dictionary, so I have to check that "1" is a dict
        elif isinstance(field_value, dict) and field_value.get("1") and \
                isinstance(field_value["1"], dict):
            # Certificate case
            cert_data = field_value.get(certificate_index, {})
            enabled = name in cert_data

        elif isinstance(field_value, dict):
            # Extensions and transparency case
            if name.isnumeric():
                # Iana code case
                enabled = name in field_value
            else:
                enabled = name in field_value.values()
            if not enabled and partial_match:
                enabled = ConditionParser._partial_match_checker(
                    field_value.values(), name)

        elif field_value and isinstance(field_value, set) and isinstance(list(field_value)[0], tuple):
            # KeyLengths case
            enabled = entry[:2] in field_value
            if not enabled and check_first:
                for field in field_value:
                    if field[0] == entry[0] and str(field[1])[:check_first] == str(entry[1])[:check_first]:
                        enabled = True

        elif isinstance(field_value, list) or isinstance(field_value, set):
            if "/" in name:
                # Groups case
                name = name.split("/")[0].strip()
            enabled = name in field_value
            if not enabled and partial_match:
                enabled = ConditionParser._partial_match_checker(
                    field_value, name)
            if not enabled and check_first:
                enabled = name[:check_first] in field_value
        elif isinstance(field_value, bool):
            enabled = field_value
        else:
            ConditionParser.__logging.warning(
                f"Invalid field: {config_field} for name: {name}")
        return enabled

    @staticmethod
    def _prepare_to_search(field, to_search):
        new_to_search = to_search
        if field.lower().startswith("protocol") or field.lower().startswith("tls"):
            new_to_search = "TLS " + to_search.strip()
        return new_to_search

    @staticmethod
    def prepare_field(field):
        # this step is needed for the upper-case letters
        field = field.replace("Certificate", "Certificate ").title()
        field = field.replace(" ", "")
        return ConditionParser._sheet_mapping.get(field, field)

    @staticmethod
    def get_check_first(condition: str):
        check_first = None
        conditions = re.split(ConditionParser._splitting_regex,
                              condition, flags=re.IGNORECASE)
        for condition in conditions:
            condition = condition.strip()
            if condition.startswith("CHECK_ONLY_FIRST") and " " in condition:
                check_first = condition.split(" ")[1]
                if check_first.isdecimal():
                    check_first = int(check_first)
                # If the condition value isn't a number it doesn't become an int and the validator gives the error.
                Validator().int(check_first)
        return check_first

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
        self.__logging.debug(f"Expression to solve: {to_solve}")
        while "(" in to_solve:
            # So that I'm sure that there aren't any parenthesis in the way
            starting_index = to_solve.index("(") + start
            end_index = self._closing_parenthesis_index(starting_index) - 1
            replacement = self._solve(starting_index + 1, end_index)
            to_replace = self.expression[starting_index:end_index + 2]
            start += len(to_replace) - len(replacement)
            to_solve = to_solve.replace(to_replace, replacement)
        to_solve = to_solve.replace("  ", " ")
        tokens = re.split(self._splitting_regex, to_solve, flags=re.IGNORECASE)
        tokens = [token.strip() for token in tokens]
        for i, token in enumerate(tokens):
            next_token = tokens[i + 1] if i < len(tokens) - 1 else None
            to_solve = to_solve.replace(token, str(
                self._evaluate_condition(token, next_token)))
        tokens = re.split(self.splitting_capturing_regex,
                          to_solve, flags=re.IGNORECASE)
        tokens = [token for token in tokens if token]
        while len(tokens) >= 3:
            first_instruction = tokens.pop(0).strip() == "True"
            logical_operation = self._operators[tokens.pop(0).lower().strip()]
            second_instruction = tokens.pop(0).strip() == "True"
            result = logical_operation(first_instruction, second_instruction)
            # After calculating the result it is inserted at the beginning of the tokens list to substitute the three
            # removed elements
            tokens.insert(0, str(result))
        return tokens[0]

    def _evaluate_condition(self, condition, next_condition=None):
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
        if condition not in self._instructions and \
                (" " not in condition and condition.split(" ")[0] not in self._instructions):
            self.__logging.warning(
                f"Invalid condition: {condition} in expression: {self.expression}. Returning False")
            return "False"
        tokens = condition.split(" ")
        field = tokens[0]
        to_search = self._prepare_to_search(field, tokens[-1])
        config_field = self._instructions.get(field.upper())
        if config_field and config_field.startswith("FUNCTION"):
            assert config_field[8] == " "
            args = {
                "data": to_search,
                "enabled": self._enabled,
                "tokens": tokens[1:],
                "next_condition": next_condition,
                "original_text": field.upper(),
                "certificate_index": self._certificate_index
            }
            result = self._custom_functions.__getattribute__(
                config_field.split(" ")[1])(**args)
        elif config_field is None:
            self.__logging.warning(
                f"Invalid field: {field} in expression: {self.expression}. Returning False")
            self.__logging.debug(f"Tokens: {tokens}")
            result = False
        else:
            # At the moment there is no need to check if a KeyLength is enabled or not, so It is possible to use
            # (None, None)
            enabled = self.is_enabled(self._user_configuration, config_field, to_search, (None, None), True,
                                      certificate_index=self._certificate_index)
            result = enabled if not negation else not enabled
        return result

    def input(self, expression, enabled, cert_index):
        self.expression = expression
        self._enabled = enabled
        self._certificate_index = cert_index

    def run(self, expression, enabled, cert_index="1"):
        if expression:
            self.input(expression, enabled, cert_index)
        return self.output()

    def output(self):
        solution = self._solve(0, len(self.expression)) == "True"
        self.entry_updates = self._custom_functions._entry_updates.copy()
        self._custom_functions.reset()
        self.__logging.debug("Solution: " + str(solution))
        return solution


class CustomFunctions:
    def __init__(self, user_configuration):
        self._user_configuration = user_configuration
        self._validator = Validator()
        self._entry_updates = {}
        self.reset()
        self._operators = {
            ">": lambda op1, op2: op1 > op2,
            "<": lambda op1, op2: op1 < op2,
            ">=": lambda op1, op2: op1 >= op2,
            "<=": lambda op1, op2: op1 <= op2,
            "==": lambda op1, op2: op1 == op2,
            "!=": lambda op1, op2: op1 != op2,
            "in": lambda op1, op2: op1 in op2,
            "not in": lambda op1, op2: op1 not in op2,
        }
        self._operators_regex = "(" + ")|( ".join(self._operators.keys()) + ")"
        self._extended_key_usage_consistency = load_configuration("extended_key_usage_consistency",
                                                                  "configs/compliance/")
        self._consistency_regex = r" x{0,1}or |[()]"
        self._logger = Logger("Custom functions")

    # INSERT ALL THE CUSTOM PARSING FUNCTIONS HERE THEY MUST HAVE SIGNATURE:
    # function(**kwargs) -> bool
    # kwargs are defined in the _evaluate_condition method of the ConditionParser class.

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
        result = parsed_date.date() > actual_date
        self._entry_updates["flip_level"] = not result
        return result

    def check_vlp(self, **kwargs):
        status = kwargs.get("data", "").lower() == "true"
        result = False
        for version in range(3):
            enabled = ConditionParser.is_enabled(
                self._user_configuration, "Protocol", f"TLS 1.{version}", (None, None))
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
                certs_trust_dict = self._user_configuration.get(
                    "TrustedCerts", {})
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
        second_condition = kwargs.get("next_condition", " ")
        certificate_index = kwargs.get("certificate_index", "1")
        tokens = second_condition.split(" ")
        field = tokens[0].title()
        name = " ".join(tokens[1:])
        # only the first two fields of the entry matter, and entry is only needed for key lengths
        entry_data = name.split(",") if "," in name else (None, None)
        if entry_data[1]:
            if not entry_data[1].isnumeric():
                self._logger.error(f"Invalid key length: {entry_data[1]}")
                return False
            entry_data = (entry_data[0], int(entry_data[1]))

        # The field must be prepared
        field = ConditionParser.prepare_field(field)
        if ";" in name:
            names = name.split(";")
            second_enabled = any(
                [ConditionParser.is_enabled(self._user_configuration, field, name, entry_data, partial_match=True,
                                            certificate_index=certificate_index) for name in names])
        else:
            second_enabled = ConditionParser.is_enabled(self._user_configuration, field, name, entry_data,
                                                        partial_match=True, certificate_index=certificate_index)
        enabled = second_enabled or enabled
        self._entry_updates["has_alternative"] = True
        self._entry_updates["is_enabled"] = enabled
        return enabled

    def add_notes(self, **kwargs):
        note = " ".join(kwargs.get("tokens", []))
        note_type = kwargs.get("original_text", "").lower()
        if not note_type or note_type == "note":
            self._logger.warning(f"No note type provided for note: `{note}`")
        elif note_type == "note_always":
            self._entry_updates["notes"].append(note)
        else:
            if not self._entry_updates.get(note_type):
                self._entry_updates[note_type] = []
            self._entry_updates[note_type].append(note)
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
        for cert in self._user_configuration["Certificate"]:
            if cert.startswith("int"):
                continue
            cert_data = self._user_configuration["Certificate"][cert]
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

    def check_value(self, **kwargs):
        tokens = kwargs.get("tokens", [])
        config_field = tokens.pop(0)
        tokens_string = " ".join(tokens)
        tokens = re.split(self._operators_regex, tokens_string)
        tokens = [t.strip() for t in tokens if t]
        value = tokens[0]
        operator = tokens[1]
        name = "".join(tokens[2:])
        # if there is a "[" and a corresponding "]" then the text inside is a level of a dictionary
        levels = re.findall(r"\[(.*?)]", name)
        if not levels:
            levels = [name]
        field = self._user_configuration.get(config_field, {})
        last_level = [
            levels[-1]] if "," not in levels[-1] else levels[-1].split(",")
        last_level = map(str.strip, last_level)
        # used the in because in this way is easier to edit if needed
        if config_field == "Certificate":
            result = True
            for cert in field:
                if cert.startswith("int"):
                    continue
                for level in last_level:
                    levels[-1] = level
                    # I pass to the function that gets the value the certificate dictionary as field
                    configuration_value = self._get_configuration_field(
                        field.get(cert, {}), levels)
                    reason = f"field {level} is missing" if not configuration_value else f"{value} {operator} {name}"
                    partial_result = self._operators[operator](
                        value, str(configuration_value))
                    for key in self._entry_updates.keys():
                        if key.startswith("note"):
                            for i, entry in enumerate(self._entry_updates[key]):
                                self._entry_updates[key][i] = entry.replace(
                                    "{cert}", cert).replace("{reason}", reason)
                    result = result and partial_result
        elif config_field == "CertificateExtensions":
            self._logger.error(
                "CertificateExtensions is not a valid field for the check_value function, use custom functions instead")
            self._logger.debug(f"Tokens: {tokens}")
            result = True
        else:
            result = True
            for level in last_level:
                levels[-1] = level
                configuration_value = self._get_configuration_field(
                    field, levels)
                partial_result = self._operators[operator](
                    value, str(configuration_value))
                reason = f"Failed check {name} {operator} {value} for {config_field}"
                for key in self._entry_updates.keys():
                    if key.startswith("note"):
                        for i, entry in enumerate(self._entry_updates[key]):
                            self._entry_updates[key][i] = entry.replace(
                                "{reason}", reason)
                result = result and partial_result
        return result

    def check_keyusage(self, **kwargs):
        """
        :param kwargs: Dictionary of arguments
        :type kwargs: dict
        :return: True if the key usage is enabled
        :rtype: bool
        :Keyword Arguments:
            * *data* (``str``) -- The key usage to check
        """
        enabled = True
        tokens = kwargs.get("tokens", [])
        tokens_string = " ".join(tokens)
        tokens = re.split(ConditionParser._splitting_regex,
                          tokens_string, flags=re.IGNORECASE)
        tokens = [t.strip() for t in tokens if t]
        if not tokens:
            raise ValueError("No key usage provided")
        self._validator.string(tokens[0])
        certificates = self._user_configuration.get(
            "CertificateExtensions", {})
        for cert in certificates:
            if cert.startswith("int"):
                continue
            cert_data = certificates[cert]
            key_usage_field = cert_data.get("keyUsage", "")
            enabled = key_usage_field.__getattribute__(tokens[0])
            reason = f"{tokens[0]} is"
            if not enabled:
                reason += " not"
            reason += " enabled in the Key Usage field"
            for key in self._entry_updates.keys():
                if key.startswith("note"):
                    for i, entry in enumerate(self._entry_updates[key]):
                        self._entry_updates[key][i] = entry.replace(
                            "{cert}", cert).replace("{reason}", reason)
        return enabled

    def check_extended_keyusage(self, **kwargs):
        """
        :param kwargs: Dictionary of arguments
        :type kwargs: dict
        :return: True if the extended key usage is enabled
        :rtype: bool
        :Keyword Arguments:
            * *data* (``str``) -- The extended key usage to check
        """
        enabled = True
        tokens = kwargs.get("tokens", [])
        tokens_string = " ".join(tokens)
        tokens = re.split(ConditionParser._splitting_regex,
                          tokens_string, flags=re.IGNORECASE)
        tokens = [t.strip() for t in tokens if t]
        if not tokens:
            raise ValueError("No extended key usage provided")
        self._validator.string(tokens[0])
        certificates = self._user_configuration.get(
            "CertificateExtensions", {})
        for cert in certificates:
            if cert.startswith("int"):
                continue
            cert_data = certificates[cert]
            extended_key_usage_field = cert_data.get("extendedKeyUsage", "")
            extended_key_usages = [
                ext_key_usage._name for ext_key_usage in extended_key_usage_field]
            enabled = tokens[0] in extended_key_usages
            reason = f"{tokens[0]} is"
            if not enabled:
                reason += " not"
            reason += " enabled in the Extended Key Usage field"
            for key in self._entry_updates.keys():
                if key.startswith("note"):
                    for i, entry in enumerate(self._entry_updates[key]):
                        self._entry_updates[key][i] = entry.replace(
                            "{cert}", cert).replace("{reason}", reason)
        return enabled

    def check_san(self, **kwargs):
        """
        :param kwargs: Dictionary of arguments
        :type kwargs: dict
        :return: True if the SAN field is enabled
        :rtype: bool
        :Keyword Arguments:
            * *data* (``str``) -- The SAN to check
        """
        enabled = True
        tokens = kwargs.get("tokens", [])
        tokens_string = " ".join(tokens)
        tokens = re.split(ConditionParser._splitting_regex,
                          tokens_string, flags=re.IGNORECASE)
        tokens = [t.strip() for t in tokens if t]
        if not tokens:
            raise ValueError("No SAN provided")
        self._validator.string(tokens[0])
        certificates = self._user_configuration.get(
            "CertificateExtensions", {})
        for cert in certificates:
            if cert.startswith("int"):
                continue
            cert_data = certificates[cert]
            san_field = cert_data.get("subjectAltName", "")
            names = [name for name in san_field]
            instance = ConditionParser.general_name_dictionary.get(
                tokens[0], None)
            if instance:
                enabled = any([isinstance(name, instance) for name in names])
            else:
                enabled = any([tokens[0] in name.value for name in names])
            reason = f"{tokens[0]} is"
            if not enabled:
                reason += " not"
            reason += " enabled in the Subject Alternative Name field"
            for key in self._entry_updates.keys():
                if key.startswith("note"):
                    for i, entry in enumerate(self._entry_updates[key]):
                        self._entry_updates[key][i] = entry.replace(
                            "{cert}", cert).replace("{reason}", reason)
        return enabled

    def check_aia(self, **kwargs):
        enabled = False
        tokens = kwargs.get("tokens", [])
        tokens_string = " ".join(tokens)
        tokens = re.split(ConditionParser._splitting_regex,
                          tokens_string, flags=re.IGNORECASE)
        tokens = [t.strip() for t in tokens if t]
        if not tokens:
            self._logger.warning(
                "No fields to check provided for AIA, returning True")
            return True
        self._validator.string(tokens[0])
        certificates = self._user_configuration.get(
            "CertificateExtensions", {})
        fields_to_check = [t.strip() for t in tokens[0].split(
            "-")] if "-" in tokens[0] else [tokens[0].strip()]
        method = fields_to_check[0]
        if len(fields_to_check) > 1:
            location = fields_to_check[1]
            valid_location = False
        for cert in certificates:
            if cert.startswith("int") or not fields_to_check:
                continue
            cert_data = certificates[cert]
            aia_field: x509.extensions.AuthorityInformationAccess = cert_data.get(
                "authorityInfoAccess", "")
            results = []
            valid_method = False
            for field in aia_field:
                valid_method = field.access_method._name == method
                if len(fields_to_check) > 1:
                    location_type = ConditionParser.general_name_dictionary.get(
                        location, None)
                    valid_location = type(
                        field.access_location) == location_type
                # if there are multiple fields only one has to be fine
                enabled = enabled or (valid_method and valid_location)

            if len(fields_to_check) > 1:
                reason = f"{method} with {location} is"
            else:
                reason = f"{tokens[0]} is"
            if not enabled:
                reason += " not"
            reason += " found in the Authority Info Access field"
            for key in self._entry_updates.keys():
                if key.startswith("note"):
                    for i, entry in enumerate(self._entry_updates[key]):
                        self._entry_updates[key][i] = entry.replace(
                            "{cert}", cert).replace("{reason}", reason)
        return enabled

    def check_crl_distribution_points(self, **kwargs):
        enabled = False
        tokens = kwargs.get("tokens", [])
        tokens_string = " ".join(tokens)
        tokens = re.split(ConditionParser._splitting_regex,
                          tokens_string, flags=re.IGNORECASE)
        tokens = [t.strip() for t in tokens if t]
        if not tokens:
            self._logger.warning(
                "No fields to check provided for crlDistributionPoints, returning True")
            return True
        fields_to_check = [t.strip() for t in tokens[0].split(
            "-")] if "-" in tokens[0] else [tokens[0].strip()]
        certificates = self._user_configuration.get(
            "CertificateExtensions", {})
        for cert in certificates:
            if cert.startswith("int"):
                continue
            cert_data = certificates[cert]
            crl_dist_points: x509.crlDistributionPoints = cert_data.get(
                "crlDistributionPoints", "")
            for point in crl_dist_points:
                enabled = enabled and point.__getattribute__(
                    tokens[0]) == tokens[0]
                if enabled and len(fields_to_check) > 1:
                    enabled = isinstance(point.__getattribute__(), ConditionParser.general_name_dictionary.get(
                        fields_to_check[1], x509.GeneralName))

            reason = f"{tokens[0]} is"
            if not enabled:
                reason += " not"
            reason += " found in the CRL Distribution Points field"
            for key in self._entry_updates.keys():
                if key.startswith("note"):
                    for i, entry in enumerate(self._entry_updates[key]):
                        self._entry_updates[key][i] = entry.replace(
                            "{cert}", cert).replace("{reason}", reason)
        return enabled

    @staticmethod
    def _get_configuration_field(field, levels):
        for level in levels:
            field = field.get(level, {})
        return field

    def check_dict_value(self, **kwargs):
        self.check_value(**kwargs)

    def check_year_in_days(self, **kwargs):
        for cert in self._user_configuration.get("Certificate", {}):
            if cert.startswith("int"):
                continue
            cert_data = self._user_configuration["Certificate"][cert]
            validity = cert_data["validity"]
            data = kwargs.get("data", None)
            if not data:
                raise ValueError("No amount of years provided")
            if not data.isnumeric():
                raise ValueError("Amount of years must be a number")
            years = int(data)
            days = years * 365
            return validity.days < days
        self._logger.debug("No certificate information found, returning True")
        return True

    def verify_scsv(self, **kwargs):
        scsv_finding = self._user_configuration.get("fallback_SCSV", "")
        enabled = "offered" in scsv_finding and "not" not in scsv_finding
        self._entry_updates["is_enabled"] = enabled
        return True

    def check_aki(self, **kwargs):
        """
        Checks for the condition: "Same as subject key identifier in issuing CA certificate; Prohibited: Issuer DN,
        Serial Number tuple"
        :param kwargs:
        :return:
        """
        self._entry_updates["is_enabled"] = False
        print(self._entry_updates)
        cert = kwargs.get("certificate_index", "1")
        failed = False
        cert_data = self._user_configuration["CertificateExtensions"].get(cert)
        if not cert_data:
            self._logger.warning(
                "No certificate information found, returning False for condition check_aki")
            self._entry_updates["is_enabled"] = False
            return True
        aki: x509.AuthorityKeyIdentifier = cert_data.get(
            "authorityKeyIdentifier", "")
        if not aki:
            self._entry_updates["notes"].append(
                f"No AKI found for certificate {cert}")
            failed = True
        if aki.authority_cert_issuer or aki.authority_cert_serial_number:
            self._entry_updates["notes"].append(
                f"Certificate {cert} contains Issuer DN or Serial Number in the AKI field")
            self._entry_updates["levels"].append("must not")
            self._entry_updates["is_enabled"] = True
            failed = True
        intermediate_certificate = self._user_configuration["CertificateExtensions"].get(
            "int_" + cert, {})
        if not intermediate_certificate:
            intermediate_certificate = self._user_configuration["CertificateExtensions"].get(
                "int_1_" + cert, {})
        if not intermediate_certificate:
            self._entry_updates["notes"].append(
                f"No intermediate certificate found for certificate {cert}")
            failed = True
        ski = intermediate_certificate.get("subjectKeyIdentifier", "")
        if not ski:
            self._entry_updates["notes"].append(
                f"No SKI found for intermediate certificate {cert}")
            failed = True
        if failed:
            # The condition must be True so that the note is shown
            return True
        result = ski.digest == aki.key_identifier
        self._entry_updates["is_enabled"] = result
        return result

    def check_same_key_usage(self, **kwargs):
        cert = kwargs.get("certificate_index", "1")
        cert_data = self._user_configuration["CertificateExtensions"].get(cert, {
        })
        if not cert_data:
            self._logger.debug(
                "No certificate information found, returning False for condition check_same_key_usage")
            self._entry_updates["is_enabled"] = False

        key_usage: x509.KeyUsage = cert_data.get("keyUsage", "")
        extended_key_usages: x509.ExtendedKeyUsage = cert_data.get(
            "extendedKeyUsage", "")
        if not key_usage or not extended_key_usages:
            self._entry_updates["notes"].append(
                f"No key usage or extended key usage found for certificate {cert}")
            return False
        key_usage = [key_usage[1:]
                     for key_usage, valid in key_usage.__dict__.items() if valid]
        extended_key_usages = [
            ext_key_usage._name for ext_key_usage in extended_key_usages]
        results = []
        findings = []
        for ext_key_usage in extended_key_usages:
            condition = self._extended_key_usage_consistency.get(
                ext_key_usage, "")
            checks = re.split(self._consistency_regex, condition)
            checks = [check.strip() for check in checks if check.strip()]
            for check in checks:
                condition = condition.replace(check, str(check in key_usage))
            result = ConditionParser(
                self._user_configuration).run(condition, True)
            results.append(result)
            if not result:
                findings.append(ext_key_usage)
        if findings:
            self._entry_updates["note_true"] = [
                f"The certificate {cert} contains extended key usages that aren't in the key usage field. "
                f"The invalid usages are: {', '.join(findings)}"]
        return not all(results)

    def disable_if(self, **kwargs):
        self._entry_updates["disable_if"] = kwargs.get("tokens", [""])[0]
        return True

    def check_dn(self, **kwargs):
        token = " ".join(kwargs.get("tokens", []))
        for cert in self._user_configuration["Certificate"]:
            cert_data = self._user_configuration["Certificate"][cert]
            dn_data = cert_data.get(token, {})
            if not dn_data:
                self._entry_updates["note_false"].append(
                    f"No DN data found for certificate {cert}")
                return False
            if not isinstance(dn_data, SequenceOf):
                self._entry_updates["note_false"].append(
                    f"Distinguished Name data found for certificate {cert} isn't a SequenceOf object")
                return False
            for dn in dn_data.components:
                if len(dn.components) != 1:
                    self._entry_updates["note_false"].append(
                        f"Certificate {cert} has more then one value encoded in its Relative Distinguished Name")
                    return False
                for rdn in dn.components:
                    component_type = rdn.components[0]
                    component_value = rdn.components[1]
                    if not isinstance(component_value, PrintableString):
                        self._entry_updates["note_false"].append(
                            f"Certificate {cert} has an attribute value that isn't a PrintableString,"
                            f" the field has oid: {component_type}")
                        return False
        return True

    def check_client_auth(self, **kwargs):
        enabled = ConditionParser.is_enabled(
            self._user_configuration, "clientAuth", "clientAuth", (None, None))
        if not enabled:
            # this is needed to not show the missing clientAuth as a note
            self._entry_updates["force_level"] = "optional"
        self._entry_updates["is_enabled"] = enabled
        return True

    def check_client_only(self, **kwargs):
        # Since we can not verify this condition we set the level to optional and return trues
        self._entry_updates["force_level"] = "optional"
        return True

    @staticmethod
    def always_true(**kwargs):
        return True

    @property
    def entry_updates(self):
        return self._entry_updates

    def reset(self):
        self._entry_updates = {"levels": [], "notes": [], "note_false": [
        ], "note_always": [], "note_true": [], "force_level": ""}
