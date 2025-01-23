import os
import re
from pathlib import Path

from apacheconfig import make_loader

from modules.compliance.configuration.configuration_base import ConfigurationMaker
from modules.configuration.configuration import Configuration
from utils.type import WebserverType


class ApacheConfiguration(ConfigurationMaker):

    def __init__(self, file: Path = None, openssl_version: str = "1.1.1"):
        super().__init__("apache", openssl_version)
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

    def add_configuration_for_field(self, field, field_rules, data, columns, guideline):
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
                                                columns, data, config_field, guideline)
        if tmp_string and tmp_string[-1] == ":":
            tmp_string = tmp_string[:-1]
        # this check prevents adding a field without any value
        if len(tmp_string) != len(config_field) + 1:
            tmp_string, comment = self.perform_post_actions(field_rules, tmp_string, guideline)
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

    def get_conf_data(self, dictionary):
        user_configuration = {}
        for directive in self.reverse_mapping:
            first_entry = ""
            name = self.reverse_mapping[directive]
            if " " in directive:
                tokens = directive.split(" ")
                directive = tokens[0]
                first_entry = tokens[1]
            user_configuration[name] = []
            value = self.configuration.get(directive)
            if first_entry and isinstance(value, list):
                start = None
                for i, entry in enumerate(value):
                    if first_entry in entry:
                        start = i
                        break
                if start is not None:
                    value = value[start]
                    value = value.split(" ")[1]
            user_configuration[name] = value
        self._set_defaults(user_configuration)
        for directive in user_configuration:
            if directive == "Protocol":
                if not dictionary.get(directive):
                    dictionary[directive] = {}
                protocols = user_configuration[directive].split(" ") if " " in user_configuration[directive] \
                    else user_configuration[directive]
                for protocol in protocols:
                    protocol = protocol.replace("v", " ")
                    enabled = protocol[0] == "+"
                    if protocol[0] in ["!", "-", "+"]:
                        protocol = protocol[1:]
                    dictionary[directive][protocol] = enabled
            elif directive in ["CipherSuites", "CipherSuitesTLS1.3"]:
                if directive == "CipherSuitesTLS1.3":
                    ciphers = user_configuration["CipherSuitesTLS1.3"]
                else:
                    ciphers = user_configuration[directive]
                directive = "CipherSuite"
                if not dictionary.get(directive):
                    dictionary[directive] = []
                ciphers = self.prepare_ciphers(ciphers)
                dictionary[directive].extend(self.expand_ciphers(ciphers))
            elif directive == "Groups":
                dictionary[directive] = user_configuration[directive].split(":") if ":" in user_configuration[directive] \
                    else user_configuration[directive]
        dictionary["CipherSuite"] = set(dictionary["CipherSuite"])