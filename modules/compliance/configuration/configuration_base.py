from pathlib import Path

from utils.database import get_standardized_level
from utils.loader import load_configuration
from utils.validation import Validator
from modules.compliance.wrappers.db_reader import Database


class ConfigurationMaker:
    def __init__(self, config_type):
        self.mapping = load_configuration("mapping", f"configs/compliance/{config_type}/")
        self.reverse_mapping = dict((v, k) for k, v in self.mapping.items())
        self._output_dict = {"configuration": config_type}
        self._config_template_path = f"configs/compliance/{config_type}/template.conf"
        self._template = None
        self._config_output = None
        self.configuration = None
        self._enabled_once = set()
        self.conditions_to_check = {}
        self._specific_rules = load_configuration("rules", f"configs/compliance/{config_type}/")
        self._actions = Actions()

    def set_out_file(self, output_file):
        """
        Used to set the output file for the config generator, if this function is called it also loads the template.
        :param output_file: Output file path
        :type output_file: Path
        """
        self._load_template()
        self._config_output = output_file

    def output_file(self):
        """
        This function returns the value of the _config_output field.
        :return: The path at which the configuration will be saved
        """
        return self._config_output

    def _load_conf(self, file: Path):
        """
        This method loads a configuration from the given path.
        :param file: Path to the configuration
        """
        raise NotImplementedError("This method should be reimplemented")

    def _load_template(self):
        """
        This method loads the template in the instance. (Needed only for generation)
        """
        raise NotImplementedError("This method should be reimplemented")

    def _write_to_file(self):
        raise NotImplementedError("This method should be reimplemented")

    def add_configuration_for_field(self, field, field_rules, data, columns, guideline, target=None):
        """
        :param field: the field that should be added (taken from configuration_rules)
        :param field_rules: the rules that should be applied to that field
        :param data: data from which to gather the field information
        :param columns: list of columns used to retrieve data from the database
        :param guideline: the guideline from which the level was deducted
        :param target: (Optional) if defined only the entries whose name contains target will be used
        :return:
        """
        raise NotImplementedError("This method should be reimplemented")

    def configuration_output(self):
        self._write_to_file()
        return self._output_dict.copy()

    def _get_string_to_add(self, field_rules, name, level, field):
        """
        :param field_rules: set of rules that should be used for this field
        :type field_rules: dict
        :param name: name of the element to evaluate
        :type name: str
        :param level: level associated with the name
        :type level: str
        :param field: Name of the field in the configuration file
        :type field: str
        :return: The string that should be added to the configuration
        :rtype: str
        """
        string_to_add = ""
        added = True
        allow_string = field_rules.get("enable", "name")
        deny_string = field_rules.get("disable", "-name")
        separator = field_rules.get("separator", " ")
        # This parameter is needed to avoid having separators even if nothing gets added to deny (like ciphersuites)
        added_negatives = field_rules.get("added_negatives", False)
        if not self._output_dict.get(field):
            self._output_dict[field] = {}
        if field in self._enabled_once:
            return ""

        if get_standardized_level(level) in ["must", "recommended"]:
            if field_rules.get("enable_one_time"):
                self._enabled_once.add(field)
            string_to_add += allow_string.replace("name", name)
            self._output_dict[field][name] = {"added": True}
        elif get_standardized_level(level) in ["must not", "not recommended"]:
            string_to_add += deny_string.replace("name", name)
            added = added_negatives
            self._output_dict[field][name] = {"added": False}
        else:
            added = False
            self._output_dict[field][name] = {"added": False}
        if added:
            string_to_add += separator

        return string_to_add

    def _prepare_field_string(self, tmp_string, field, field_rules, name_index, level_index, condition_index, columns, data,
                              config_field, guideline, target):
        for entry in data:
            condition = ""
            if isinstance(entry, dict):
                name = entry["entry"][name_index]
                level = entry["level"]
                guideline = entry["source"]
                if guideline in entry["entry"]:
                    guideline_pos = entry["entry"].index(guideline)
                    # to get the condition for the guideline I calculate guideline's index and then search it near it
                    step = len(columns)
                    guideline_counter = guideline_pos // step
                    condition = entry["entry"][condition_index + guideline_counter * step]
            else:
                name = entry[name_index]
                level = entry[level_index]
                condition = entry[condition_index]

            if target and target.replace("*", "") not in name:
                continue

            replacements = field_rules.get("replacements", [])
            for replacement in replacements:
                name = name.replace(replacement, replacements[replacement])
            tmp_string += self._get_string_to_add(field_rules, name, level, field)
            if self._output_dict[field].get(name):
                if condition:
                    index = len(self.conditions_to_check)
                    self.conditions_to_check[index] = {
                        "columns": columns,
                        "data": data,
                        "expression": condition,
                        "field": config_field,
                        "guideline": guideline,
                        "level": level,
                        "name": name,
                    }
                self._output_dict[field][name]["guideline"] = guideline
        return tmp_string

    def perform_post_actions(self, field_rules, actual_string, guideline):
        comment = ""
        if field_rules.get("post_actions", None):
            for action in field_rules["post_actions"]:
                arguments = field_rules["post_actions"][action]
                if action.startswith("comment"):
                    comment = self._actions.__getattribute__(action)(**{"value": comment, "arguments": arguments,
                                                                        "guideline": guideline,
                                                                        "actual_string": actual_string})
                else:
                    actual_string = self._actions.__getattribute__(action)(**{"value": actual_string,
                                                                              "arguments": arguments})
        return actual_string, comment

    @property
    def output_dict(self):
        return self._output_dict

# This class is used to define the actions that can be taken after a field has been prepared and before it gets added to
# the configuration file. The actions are defined in the configuration_rules file using the post_actions key with value
# a list of actions to take, the function_name and the arguments are separated by a blank space ` `.
class Actions:
    def __init__(self):
        self.validator = Validator()
        self._ciphers_converter = load_configuration("iana_to_openssl", "configs/compliance/")
        self._database = Database()
    def split(self, **kwargs) -> list:
        """
        :param kwargs: Dictionary of arguments
        :type kwargs: dict
        :return: True if the year indicated has already passed
        :rtype: bool
        :Keyword Arguments:
            * *value* (``str``) -- String to split
            * *arguments* (``str``) -- Separator to use
        """
        value = kwargs.get("value", None)
        separator = kwargs.get("arguments", None)
        self.validator.string(value)
        self.validator.string(separator)
        return [v for v in value.split(separator) if v]

    def convert_ciphers(self, **kwargs) -> str:
        """
        :param kwargs: Dictionary of arguments
        :type kwargs: dict
        :return: the list of converted ciphers
        :rtype: str
        :Keyword Arguments:
            * *value* (``str``) -- String to convert
        """
        string = kwargs.get("value", None)
        self.validator.string(string)
        for cipher in self._ciphers_converter:
            if self._ciphers_converter[cipher]:
                string = string.replace(cipher, self._ciphers_converter[cipher])
        return string

    def convert_groups(self, **kwargs) -> str:
        # TODO add to report a message stating that this directive is not supported by OpenSSL prior to 1.0.2
        """
        :param kwargs: Dictionary of arguments
        :type kwargs: dict
        :return: the list of converted groups
        :rtype: str
        :Keyword Arguments:
            * *value* (``str``) -- String to convert
        """
        string = kwargs.get("value", None)
        self.validator.string(string)
        for group in string.split(":"):
            if "/" in group:
                string = string.replace(group, group.split("/")[0].strip())
        return string

    def prepend(self, **kwargs):
        """
        :param kwargs: Dictionary of arguments
        :type kwargs: dict
        :return: the string with arguments prepended
        :rtype: str
        :Keyword Arguments:
            * *value* (``str``) -- String to convert
        """
        string = kwargs.get("value", None)
        other_string = kwargs.get("arguments", None)
        self.validator.string(string)
        self.validator.string(other_string)
        return other_string + string

    def prepend_after(self, **kwargs):
        string = kwargs.get("value", None)
        arguments = kwargs.get("arguments", None)
        self.validator.string(string)
        self.validator.dict(arguments)
        other_string = kwargs["arguments"].get("string", None)
        separator = kwargs["arguments"].get("separator", None)
        self.validator.string(other_string)
        self.validator.string(separator)
        if separator in string:
            parts = string.split(separator, 1)
            parts[1] = other_string + parts[1]
            string = separator.join(parts)
        return string

    def comment(self, **kwargs):
        """
        :param kwargs: Dictionary of arguments
        :type kwargs: dict
        :return: the value of the arguments concatenated to the actual comment string
        :rtype: str
        """
        string = kwargs.get("value", None)
        arguments = kwargs.get("arguments", None)
        self.validator.string(string)
        self.validator.string(arguments)
        return string + arguments

    def comment_format(self, **kwargs):
        """
        :param kwargs: Dictionary of arguments
        :type kwargs: dict
        :return: the formatted comment string
        :rtype: str
        :Keyword Arguments:
            * *value* (``str``) -- String to format
            * *arguments* (``str``) -- Dictionary of arguments with form position: function_name
            * *guideline* (``str``) -- Guideline from which to get the information
        """
        string = kwargs.get("value", None)
        arguments = kwargs.get("arguments", None)
        guideline = kwargs.get("guideline", None)
        self.validator.string(string)
        self.validator.dict(arguments)
        self.validator.string(guideline)
        format_values = [""*len(arguments)]
        for position in arguments:
            format_values[int(position)] = self.__getattribute__(arguments[position])(**{"value": string,
                                                                                         "guideline": guideline})
        return string.format(*format_values)

    def dhparam(self, **kwargs):
        """
        :param kwargs: Dictionary of arguments
        :type kwargs: dict
        :return: the dhparam length for the guideline
        :rtype: str
        :Keyword Arguments:
            * *value* (``str``) -- String to format
            * *guideline* (``str``) -- Guideline from which to get the information
        """
        guideline = kwargs.get("guideline", None)
        self.validator.string(guideline)
        values = self._database.run([guideline], columns=["length", "level"],
                                    other_filter="WHERE name = \"DH\" AND (level = \"must\" OR level = \"recommended\")")
        value = values[-1][0]
        return value


