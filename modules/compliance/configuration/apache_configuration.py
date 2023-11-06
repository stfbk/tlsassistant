import os
import re
from pathlib import Path

from apacheconfig import make_loader

from modules.compliance.configuration.configuration_base import ConfigurationMaker
from modules.configuration.configuration import Configuration
from utils.type import WebserverType


class ApacheConfiguration(ConfigurationMaker):

    def __init__(self, file: Path = None):
        super().__init__("apache")
        self._string_to_add = ""
        if file:
            self._load_conf(file)

    # Borrowing this function from Configuration for testing purposes
    def _load_conf(self, file: Path):
        """
        Internal method to load the apache configuration file.

        :param file: path to the configuration file
        :type file: str
        """
        self.configuration = Configuration(path=str(file), type_=WebserverType.APACHE).get_conf()

    def _load_template(self):
        with open(self._config_template_path, "r") as f:
            self._template = f.read()

    def add_configuration_for_field(self, field, field_rules, data, columns, guideline, target=None):
        config_field = self.mapping.get(field, None)
        name_index = columns.index("name")
        level_index = columns.index("level")
        condition_index = columns.index("condition")
        self._output_dict[field] = {}

        if config_field is None:
            # This field isn't available with this configuration
            return
        tmp_string = config_field + " "
        field_rules = self._specific_rules.get(field, field_rules)
        tmp_string = self._prepare_field_string(tmp_string, field, field_rules, name_index, level_index, condition_index,
                                                columns, data, config_field, guideline, target)
        if tmp_string and tmp_string[-1] == ":":
            tmp_string = tmp_string[:-1]
        # this check prevents adding a field without any value
        if len(tmp_string) != len(config_field) + 1:
            tmp_string, comment = self._perform_post_actions(field_rules, tmp_string, guideline)
            if comment:
                comment = "#" + comment
            self._string_to_add += "\n" + comment + tmp_string

    def remove_field(self, field, name):
        lines = self._string_to_add.splitlines()
        to_remove = []
        for i, line in enumerate(lines):
            if line.strip().startswith(field):
                if ":" in line:
                    line = line.replace(name, "")
                    lines[i] = re.sub("::*", ":", line)
                else:
                    to_remove.append(line)
        for line in to_remove:
            lines.remove(line)
        self._string_to_add = "\n".join(lines)

    def _write_to_file(self):
        if not os.path.isfile(self._config_template_path):
            raise FileNotFoundError("Invalid template file")

        with open(self._config_output, "w") as f:
            f.write(self._template + self._string_to_add)
