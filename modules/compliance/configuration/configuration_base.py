from pathlib import Path

from utils.database import get_standardized_level
from utils.loader import load_configuration


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
        self._specific_rules = load_configuration("rules", f"configs/compliance/{config_type}/")

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

    def add_configuration_for_field(self, field, field_rules, data, name_index, level_index, guideline, target=None):
        """
        :param field: the field that should be added (taken from configuration_rules)
        :param field_rules: the rules that should be applied to that field
        :param data: data from which to gather the field information
        :param name_index: index of the name column
        :param level_index: index of the level column
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
