from pathlib import Path

from modules.compliance import compliance_base
from modules.compliance.wrappers.conditionparser import ConditionParser
from modules.compliance.wrappers.db_reader import Database
from modules.configuration.configuration_base import OpenSSL
from utils.ciphersuites import get_1_3_ciphers
from utils.database import get_standardized_level
from utils.loader import load_configuration
from utils.logger import Logger
from utils.validation import Validator


class ConfigurationMaker:
    def __init__(self, config_type, openssl_version):
        self.mapping = load_configuration(
            "mapping", f"configs/compliance/{config_type}/")
        self.reverse_mapping = dict((v, k) for k, v in self.mapping.items())
        self._output_dict = {"configuration": config_type}
        self._config_template_path = f"configs/compliance/{config_type}/template.conf"
        self._template = None
        self._config_output = None
        self.configuration = None
        self._enabled_once = set()
        self.conditions_to_check = {}
        self._specific_rules = load_configuration(
            "rules", f"configs/compliance/{config_type}/")
        self._actions = Actions(openssl_version)
        self._logger = Logger("Configuration maker")
        self.signature_algorithms = load_configuration(
            "sigalgs", "configs/compliance/")
        self._tags_mapping = load_configuration(
            "tags_mapping", "configs/compliance/")
        self._tags = set()
        self._ciphers_tags = load_configuration(
            "ciphersuites_tags", "configs/compliance/")
        self._groups_defaults = load_configuration(
            "groups_defaults", "configs/compliance/")
        self._database_instance = Database()

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

    def add_configuration_for_field(self, field, field_rules, data, columns, guideline):
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
        level = get_standardized_level(level)
        if level in ["must", "recommended"] or field_rules.get("enable_optional") and level == "optional":
            if field_rules.get("enable_one_time"):
                self._enabled_once.add(field)
            string_to_add += allow_string.replace("name", name)
            self._output_dict[field][name] = {"added": True}
        elif level in ["must not", "not recommended"]:
            string_to_add += deny_string.replace("name", name)
            added = added_negatives
            self._output_dict[field][name] = {"added": False}
        else:
            added = False
            self._output_dict[field][name] = {"added": False}
        self._output_dict[field][name]["level"] = level
        if added:
            string_to_add += separator

        return string_to_add

    def _prepare_field_string(self, tmp_string, field, field_rules, name_index, level_index, condition_index, columns,
                              data, config_field, guideline):
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
                    condition = entry["entry"][condition_index +
                                               guideline_counter * step]
            else:
                name = entry[name_index]
                level = entry[level_index]
                condition = entry[condition_index]

            replacements = field_rules.get("replacements", [])
            for replacement in replacements:
                name = name.replace(replacement, replacements[replacement])
            tmp_string += self._get_string_to_add(
                field_rules, name, level, field)
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
                self._output_dict[field][name]["source"] = guideline
                self._output_dict[field][name]["configuration_field"] = config_field
                addition_string = "not added because of"
                if level in ["must", "recommended", "optional"]:
                    addition_string = "was added with required"
                self._output_dict[field][name][
                    "action"] = f"{addition_string} level {level.upper()}"
        return tmp_string

    def perform_post_actions(self, field_rules, actual_string, guideline, actions_from="post_actions"):
        comment = ""
        if field_rules.get(actions_from, None):
            for action in field_rules[actions_from]:
                arguments = field_rules[actions_from][action]
                if action.startswith("comment"):
                    comment = self._actions.__getattribute__(action)(**{"value": comment, "arguments": arguments,
                                                                        "guideline": guideline,
                                                                        "actual_string": actual_string})
                else:
                    actual_string = self._actions.__getattribute__(action)(**{"value": actual_string,
                                                                              "arguments": arguments})
        if self._actions._output_data:
            if self._output_dict.get("post_actions_output") is None:
                self._output_dict["post_actions_output"] = dict()
            self._output_dict["post_actions_output"].update(
                self._actions._output_data)
            self._actions._output_data = {}
        return actual_string, comment

    def set_openssl_version(self, version):
        self._actions.openssl_version = version

    def set_security(self, security):
        self._actions._security = security

    @property
    def output_dict(self):
        return self._output_dict

    def get_conf_data(self, dictionary):
        raise NotImplementedError("This method should be reimplemented")

    def _set_defaults(self, user_configuration: dict):
        openssl_version = self._actions.openssl_version
        if not user_configuration.get("CipherSuites"):
            default_ciphers = self._ciphers_tags["releases_default"].get(
                openssl_version, "")
            if not default_ciphers:
                self._logger.warning(
                    "No default ciphersuites found for the current openssl version")
            elif isinstance(default_ciphers, tuple):
                default_ciphers = default_ciphers[0]
            user_configuration["CipherSuites"] = default_ciphers
        if not user_configuration.get("CipherSuitesTLS1.3"):
            default_ciphers = self._ciphers_tags["releases_default"].get(
                openssl_version, "")
            if not default_ciphers:
                self._logger.warning(
                    "No default ciphersuites found for the current openssl version")
            elif isinstance(default_ciphers, tuple):
                default_ciphers = default_ciphers[1]
            elif isinstance(default_ciphers, str):
                default_ciphers = ""
            user_configuration["CipherSuites"] = default_ciphers
        if not user_configuration.get("Groups"):
            user_configuration["Groups"] = self._groups_defaults.get(
                openssl_version, "")
            if not user_configuration["Groups"]:
                self._logger.warning(
                    "No default groups found for the current openssl version")

    @staticmethod
    def prepare_ciphers(ciphers: str):
        ciphers = ciphers.split(":") if ":" in ciphers else [ciphers]
        ciphers_list = []
        for i, cipher in enumerate(ciphers):
            status = "enabled"
            if cipher[0] == "!":
                status = "killed"
                cipher = cipher[1:]
            elif cipher[0] == "-":
                status = "removed"
                cipher = cipher[1:]
            ciphers_list.append((cipher, status))
        return ciphers_list

    def expand_ciphers(self, ciphers: list):
        openssl_version = self._actions.openssl_version
        tags_mapping = self._tags_mapping[openssl_version[:2]]
        to_remove = set()
        killed = set()
        new_list = [cipher[0] for cipher in ciphers]
        for i, cipher in enumerate(ciphers):
            cipher_name = cipher[0]
            cipher_status = cipher[1]
            if cipher_name in tags_mapping:
                to_remove.add(cipher_name)
                ciphers_list = self._ciphers_list(cipher_name)
                ciphers_list = set(ciphers_list)
                if cipher_status == "removed":
                    to_remove.update(ciphers_list)
                elif cipher_status == "killed":
                    killed.update(ciphers_list)
                else:
                    for el in ciphers_list:
                        new_list.insert(i, el)
                        if el in to_remove:
                            to_remove.remove(el)
            elif cipher_status == "killed":
                killed.add(cipher_name)
            elif cipher_status == "removed":
                to_remove.add(cipher_name)

        to_remove.update(killed)
        for el in new_list:
            if el in to_remove:
                new_list.remove(el)
        return new_list

    def _ciphers_list(self, cipher):
        openssl_version = self._actions.openssl_version
        tags_mapping = self._tags_mapping[openssl_version[:2]]
        ciphers = []
        filters = {}
        for entry in tags_mapping[cipher]:
            if entry != "releases":
                filters[entry] = tags_mapping[cipher][entry]
        update = tags_mapping[cipher]["releases"].get(openssl_version, {})
        if update is None:
            return []
        if isinstance(update, dict):
            for key in update:
                filters[key] = update[key]
        positive_filers = set()
        negative_filters = set()
        for tag in filters:
            final_tag = filters[tag]
            if "&" in final_tag:
                final_tags = final_tag.split("&")
            elif "|" in final_tag:
                final_tags = final_tag.split("|")
            else:
                final_tags = [final_tag]

            for final_tag in final_tags:
                if final_tag[0] == "~":
                    negative_filters.add(final_tag[1:])
                else:
                    positive_filers.add(final_tag)
        for ciphersuite in self._ciphers_tags:
            if "release" in ciphersuite:
                continue
            tmp_values = list(self._ciphers_tags[ciphersuite].values())
            to_remove = None
            for i, el in enumerate(tmp_values):
                if isinstance(el, dict):
                    to_remove = i
            if to_remove:
                tmp_values.pop(to_remove)
            value = set(tmp_values)
            if positive_filers.issubset(value) and not negative_filters.intersection(value):
                ciphers.append(ciphersuite)
        return ciphers


# This class is used to define the actions that can be taken after a field has been prepared and before it gets added to
# the configuration file. The actions are defined in the configuration_rules file using the post_actions key with value
# a list of actions to take, the function_name and the arguments are separated by a blank space ` `.
class Actions:
    def __init__(self, openssl_version):
        self.validator = Validator()
        self._ciphers_converter = load_configuration(
            "iana_to_openssl", "configs/compliance/")
        self._database = Database()
        self.openssl_version = openssl_version
        self._logger = Logger("Configuration actions")
        self._openssl = OpenSSL()
        self._sigalgs_table = load_configuration(
            "sigalgs_iana_to_ietf", "configs/compliance/")
        self.signature_algorithms = load_configuration(
            "sigalgs", "configs/compliance/")
        self.tls1_3_ciphers = get_1_3_ciphers()
        self._condition_parser = ConditionParser({})
        self._dh_converter = load_configuration(
            "dhparams_mapping", "configs/compliance/")
        self.security = True
        self._output_data = {}

    def clean_final_string(self, string):
        while "::" in string:
            string = string.replace("::", ":")
        if string[-1] == ":":
            string = string[:-1]
        return string

    def split(self, **kwargs) -> list:
        """
        :param kwargs: Dictionary of arguments
        :type kwargs: dict
        :return: the result of the split function called on a string
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

    def replace(self, **kwargs) -> str:
        """
        :param kwargs: Dictionary of arguments
        :type kwargs: dict
        :return: the result of the replace function
        :param kwargs:
        :Keyword Arguments:
            * *value* (``str``) -- String to replace
            * *arguments* (``dict``) -- a dict containing as keys the string to replace and as values the replacement
        """
        value = kwargs.get("value", None)
        arguments = kwargs.get("arguments", None)
        self.validator.string(value)
        self.validator.dict(arguments)
        for argument in arguments:
            value = value.replace(argument, arguments[argument])
        return value

    def convert_ciphers(self, **kwargs) -> str:
        """
        :param kwargs: Dictionary of arguments
        :type kwargs: dict
        :return: the list of converted ciphers
        :rtype: str
        """
        string = kwargs.get("value", None)
        dict_key = kwargs.get("arguments", "undefined_sheet")
        if self._output_data.get(dict_key) is None:
            self._output_data[dict_key] = {}
        self._output_data[dict_key]["convert_ciphers"] = {}
        self.validator.string(string)
        for cipher in self._ciphers_converter:
            if not self._ciphers_converter[cipher]:
                self._logger.debug(
                    f"Skipping cipher: {cipher} because it is not supported by the current OpenSSL version")
                if cipher in string:
                    self._output_data[dict_key]["convert_ciphers"][cipher] = "Not supported by this OpenSSL version"
                    self._output_data[dict_key]["convert_ciphers"]["missing_elements"] = True
            string = string.replace(cipher, self._ciphers_converter[cipher])
        while "::" in string:
            string = string.replace("::", ":")
        if string[-1] == ":":
            string = string[:-1]
        return string

    def convert_groups(self, **kwargs) -> str:
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
        groups = string.split(":") if ":" in string else [string]
        if self._openssl.less_than(self.openssl_version, "1.0.2"):
            self._logger.warning(
                "The provided openssl version can not use multiple groups, only the first one will be used.")
            groups = groups[:1]
            string = string.split(":")[0]
        for group in groups:
            if "/" in group and not group.startswith("<br"):
                string = string.replace(group, group.split("/")[0].strip())
            if "long DH" in group:
                string = string.replace(group, "")
        string = self.clean_final_string(string)
        return string

    def convert_sigalgs(self, **kwargs) -> str:
        """
        :param kwargs: Dictionary of arguments
        :type kwargs: dict
        :return: the list of converted sigalgs
        :param kwargs:
        :return:
        """
        string = kwargs.get("value", None)
        self.validator.string(string)
        dict_key = kwargs.get("arguments", "undefined_sheet")
        if self._output_data.get(dict_key) is None:
            self._output_data[dict_key] = {}
        self._output_data[dict_key]["convert_sigalgs"] = {}
        sigalgs = string.split(":") if ":" in string else [string]
        sigalgs = [sigalg for sigalg in sigalgs if sigalg.strip()]
        sigalgs = [sigalg.split(
            " ")[-1] if " " in sigalg else sigalg for sigalg in sigalgs]
        if sigalgs[0] == "<code>":
            sigalgs = sigalgs[1:]
        elif sigalgs[0].startswith("<code>"):
            sigalgs[0] = sigalgs[0].replace("<code>", "")
        for i, sigalg in enumerate(sigalgs):
            sigalgs[i] = self._sigalgs_table.get(sigalg, sigalg)
            string = string.replace(sigalg, sigalgs[i])
        if self._openssl.greater_than(self.openssl_version, "1.1.0"):
            for sigalg in sigalgs:
                if sigalg not in self.signature_algorithms[self.openssl_version]:
                    self._logger.info(
                        f"Signature algorithm {sigalg} can not be enabled with the current OpenSSL version")
                    string = string.replace(sigalg, "")
                    self._output_data[dict_key]["convert_sigalgs"][sigalg] = "Not supported by this OpenSSL version"
                    self._output_data[dict_key]["convert_sigalgs"]["missing_elements"] = True
        else:
            self._output_data[dict_key]["convert_sigalgs"]["issue"] = "in order to configure signature algorithms, you need to upgrade to OpenSSL 1.1.1 or later."
        string = self.clean_final_string(string)
        return string.replace("<code>:", "<code>")

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
        sheet = arguments.pop("sheet", "undefined_sheet")
        if self._output_data.get(sheet) is None:
            self._output_data[sheet] = {}
            self._output_data[sheet]["comment_format"] = {}
        user_action = arguments.pop("user_action", False)
        additional_text = arguments.pop("add_text_in_report", "")
        format_values = ["" * len(arguments)]
        for position in arguments:
            format_values[int(position)] = self.__getattribute__(arguments[position])(**{"value": string,
                                                                                         "guideline": guideline})
        final_string = string.format(*format_values)
        final_dict_string = "user_action" if user_action else "comment_format"
        self._output_data[sheet]["comment_format"][final_dict_string] = final_string + additional_text
        return string

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
        columns = ["length", "level", "condition"]
        columns_orig = columns.copy()
        query_filter = "WHERE name = \"DH\" AND level in (\"must\", \"recommended\")"
        join_condition = ""
        guidelines = guideline.split(",") if "," in guideline else [guideline]
        if len(guidelines) > 1:
            columns = []
            filters = []
            query_filter = f"WHERE {guidelines[0]}.name = \"DH\" AND ("
            join_condition += "ON "
            for token in guidelines:
                for column in columns_orig:
                    columns.append(token + "." + column)
                filters.append(f"{token}.level in (\"must\", \"recommended\")")
            join_condition += ".id == ".join(guidelines) + ".id"
            query_filter += " OR ".join(filters) + ")"
        values = self._database.run(tables=guidelines, columns=columns,
                                    other_filter=query_filter, join_condition=join_condition)
        valid_sizes = {}
        entries = []
        # The entries are split here to make the evaluation of the condition easier
        for entry in values:
            for i in range(0, len(entry), len(columns_orig)):
                entries.append(entry[i:i + len(columns_orig)])
        for entry in entries:
            if len(entry) == len(columns_orig):
                condition = entry[columns_orig.index("condition")]
                valid_condition = True
                if condition:
                    valid_condition = self._condition_parser.run(
                        condition, enabled=True)
                enabled = self._condition_parser.entry_updates.get(
                    "is_enabled", True)
                level = entry[columns_orig.index("level")]
                if self._condition_parser.entry_updates.get("levels"):
                    potential_levels = self._condition_parser.entry_updates.get(
                        "levels")
                    level = compliance_base.Compliance.level_to_use(
                        potential_levels, self.security)
                level = self._condition_parser.entry_updates.get(
                    "force_level", level)
                if valid_condition and enabled:
                    length = entry[columns_orig.index("length")]
                    if valid_sizes.get(length) is None:
                        valid_sizes[length] = []
                    valid_sizes[length].append(level)
        for length in valid_sizes:
            valid_index = compliance_base.Compliance.level_to_use(
                valid_sizes[length], self.security)
            valid_sizes[length] = valid_sizes[length][valid_index]
        # remove all the levels that should not be enabled from the dict
        valid_sizes = dict((k, v) for k, v in valid_sizes.items() if v not in [
                           "must not", "not recommended"])
        levels = list(valid_sizes.values())
        resulting_level = compliance_base.Compliance.level_to_use(
            levels, self.security)
        length = list(valid_sizes.keys())[resulting_level]
        return self._dh_converter.get(str(length), "No dhparam available")

    def strip(self, **kwargs):
        """
        :param kwargs: Dictionary of arguments
        :type kwargs: dict
        :return: the stripped string
        :rtype: str
        :Keyword Arguments:
            * *value* (``str``) -- String to strip
            * *arguments* (``list``) -- List of strings to strip
        """
        string = kwargs.get("value", None)
        arguments = kwargs.get("arguments", None)
        self.validator.string(string)
        self.validator.list(arguments)
        for argument in arguments:
            string = string.strip(argument)
        return string
