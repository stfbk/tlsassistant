import os

from utils.loader import load_configuration


class ConfigurationMaker:
    def __init__(self, config_type):
        self.mapping = load_configuration("mapping", f"configs/compliance/{config_type}/")
        self.reverse_mapping = dict((v, k) for k, v in self.mapping.items())
        self._output_dict = {}
        self._string_to_add = ""
        self._config_template = f"configs/compliance/{config_type}/template.conf"
        self._config_output = None
        self.configuration = None
        self._specific_rules = load_configuration("rules", f"configs/compliance/{config_type}/")

    def output_file(self):
        return self._config_output

    def set_template(self, path):
        self._config_template = path

    def set_out_file(self, path):
        self._config_output = path

    def _load_template(self):
        if not os.path.isfile(self._config_template):
            raise FileNotFoundError("Invalid template file")
        with open(self._config_template, "r") as f:
            return f.read()

    def add_configuration_for_field(self, field, field_rules, data, name_index, level_index):
        """
        :param field: the field that should be added (taken from configuration_rules)
        :param field_rules:
        :param data:
        :param name_index:
        :param level_index:
        :return:
        """
        raise NotImplementedError("This method should be reimplemented")

    def write_to_file(self):
        """
        Loads the template, adds the new text and writes the result to the output_file.
        :return: a dictionary containing a report of what was added and what not
        """
        with open(self._config_output, "w") as f:
            f.write(self._load_template() + "\n" + self._string_to_add)
        return self._output_dict.copy()
