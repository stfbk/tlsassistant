import datetime
import re

from utils.loader import load_configuration
from utils.logger import Logger
from utils.validation import Validator


class ConditionParser:
    _logical_separators = ["and", "or"]
    # simple regex to find all occurrences of the separators
    _splitting_regex = "|".join(_logical_separators)
    # same as above but also captures the separators
    _splitting_capturing_regex = "(" + ")|(".join(_logical_separators) + ")"
    # mapping from field indicator used in the conditions to the field of the configuration dictionary

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
        field_value = user_configuration.get(config_field, None)
        check_first = None

        if condition:
            check_first = ConditionParser.get_check_first(condition)

        enabled = False
        if isinstance(field_value, dict) and isinstance(field_value.get(name), bool):
            # Protocols case
            enabled = field_value.get(name, None)
            if enabled is None:
                enabled = True if "all" in field_value else False

        elif isinstance(field_value, dict) and field_value.get("1"):
            # Certificate case
            cert_data = field_value.get(certificate_index, {})
            enabled = name in cert_data
            print(cert_data, name)

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
            if not enabled and check_first:
                enabled = name[:check_first] in field_value
        return enabled

    @staticmethod
    def _prepare_to_search(field, to_search):
        new_to_search = to_search
        if field == "TLS":
            new_to_search = "TLS " + to_search.strip()
        return new_to_search

    @staticmethod
    def get_check_first(condition: str):
        check_first = None
        conditions = re.split(ConditionParser._splitting_regex, condition, flags=re.IGNORECASE)
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

        while "(" in to_solve:
            # So that I'm sure that there aren't any parenthesis in the way
            starting_index = to_solve.index("(") + start
            end_index = self._closing_parenthesis_index(starting_index) - 1
            replacement = self._solve(starting_index + 1, end_index)
            to_replace = self.expression[starting_index:end_index + 2]
            to_solve = to_solve.replace(to_replace, replacement)
        tokens = re.split(self._splitting_regex, to_solve, flags=re.IGNORECASE)
        tokens = [token.strip() for token in tokens]
        for i, token in enumerate(tokens):
            next_token = tokens[i + 1] if i < len(tokens) - 1 else None
            to_solve = to_solve.replace(token, str(self._evaluate_condition(token, next_token)))
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
                "tokens": tokens[1:],
                "next_condition": next_condition
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
            "==": lambda op1, op2: op1 == op2,
            "!=": lambda op1, op2: op1 != op2,
            "in": lambda op1, op2: op1 in op2,
            "not in": lambda op1, op2: op1 not in op2,
        }
        self._operators_regex = "(" + ")|(".join(self._operators.keys()) + ")"

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
        second_condition = kwargs.get("next_condition", " ")
        tokens = second_condition.split(" ")
        field = tokens[0]
        name = " ".join(tokens[1:])
        # only the first two fields of the entry matter, and entry is only needed for key lengths
        entry_data = name.split(",") if "," in name else (None, None)
        second_enabled = ConditionParser.is_enabled(self._user_configuration, field, name, entry_data,
                                                    partial_match=True)
        enabled = second_enabled or enabled
        self._entry_updates["has_alternative"] = enabled
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
        last_level = [levels[-1]] if "," not in levels[-1] else levels[-1].split(",")
        last_level = map(str.strip, last_level)
        # used the in because in this way is easier to edit if needed
        if config_field in ["Certificate", "CertificateExtensions"]:
            result = True
            for cert in field:
                for level in last_level:
                    levels[-1] = level
                    # I pass to the function that gets the value the certificate dictionary as field
                    configuration_value = self._get_configuration_field(field.get(cert, {}), levels)
                    reason = f"field {level} is missing" if not configuration_value else f"{value} {operator} {name}"
                    partial_result = self._operators[operator](value, str(configuration_value))
                    if not partial_result or len(configuration_value) == 0:
                        self._entry_updates["notes"].append(f"Certificate {cert} failed check, reason: {reason}")
                    result = result and partial_result
        else:
            result = True
            for level in last_level:
                levels[-1] = level
                configuration_value = self._get_configuration_field(field, levels)
                partial_result = self._operators[operator](value, str(configuration_value))
                if not partial_result:
                    self._entry_updates["notes"].append(f"Failed check {name} {operator} {value} for {config_field}")
                result = result and partial_result
        return result

    @staticmethod
    def _get_configuration_field(field, levels):
        for level in levels:
            field = field.get(level, {})
        return field

    def check_dict_value(self, **kwargs):
        self.check_value(**kwargs)

    def check_year_in_days(self, **kwargs):
        # todo implement this
        return True

    @staticmethod
    def always_true(**kwargs):
        return True

    @property
    def entry_updates(self):
        return self._entry_updates

    def reset(self):
        self._entry_updates = {"levels": [], "notes": []}
