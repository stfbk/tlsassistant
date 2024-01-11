import os
import re
from pathlib import Path

from crossplane import build as nginx_build

from modules.compliance.configuration.configuration_base import ConfigurationMaker
from modules.configuration.configuration import Configuration
from utils.type import WebserverType


class NginxConfiguration(ConfigurationMaker):
    def __init__(self, file: Path = None, openssl_version: str = "1.1.1"):
        super().__init__("nginx", openssl_version)
        if file:
            self._load_conf(file)

    # Borrowing this function from Configuration for testing purposes
    def _load_conf(self, file: Path):
        """
        Internal method to load the nginx configuration file.

        :param file: path to the configuration file
        :type file: str
        """
        self.configuration = Configuration(path=str(file), type_=WebserverType.NGINX, process=False).get_conf()

    def add_configuration_for_field(self, field, field_rules, data, columns, guideline, target=None):
        config_field = self.mapping.get(field, None)
        name_index = columns.index("name")
        level_index = columns.index("level")
        condition_index = columns.index("condition")
        self._output_dict[field] = {}

        if not config_field:
            # This field isn't available with this configuration
            return

        tmp_string = ""
        field_rules = self._specific_rules.get(field, field_rules)
        tmp_string = self._prepare_field_string(tmp_string, field, field_rules, name_index, level_index,
                                                condition_index,
                                                columns, data, config_field, guideline, target)
        if tmp_string and tmp_string[-1] == ":":
            tmp_string = tmp_string[:-1]
        tmp_string = tmp_string.strip()
        # this is to prevent adding a field without any value
        if tmp_string:
            # The directive gets added at the beginning of the http directive
            # the breakdown of the below instruction is:
            # loaded_template: dictionary
            # config: list of loaded files (in this case one)
            # parsed: list of dictionaries that represent directives (1 is the http directive)
            # block: list of dictionaries that represent directives inside the directive got before
            # each directive has a directive field for the name and an args (list) one for the params it should have
            # The args value is a list only containing tmp_string because the params are prepared while reading them.
            args = tmp_string
            args, comment = self.perform_post_actions(field_rules, args, guideline)
            if not isinstance(args, list):
                args = [args]
            directive_to_add = {"directive": config_field, "args": args}
            self._template["config"][0]["parsed"][1]["block"].insert(0, directive_to_add)
            if comment:
                directive_to_add = {"directive": "#", "comment": comment}
                self._template["config"][0]["parsed"][1]["block"].insert(0, directive_to_add)

    def remove_field(self, field, name=None):
        to_remove = []
        for directive in self._template["config"][0]["parsed"][1]["block"]:
            if directive.get("directive") == field:
                to_remove.append(directive)
        for directive in to_remove:
            found = False
            if name:
                for i, element in enumerate(directive["args"]):
                    if name in element:
                        directive["args"][i] = element.replace(name, "")
                        directive["args"][i] = re.sub("::*", ":", directive["args"][i])
                        found = True
            if not found:
                self._template["config"][0]["parsed"][1]["block"].remove(directive)

    def _load_template(self):
        self._load_conf(Path(self._config_template_path))
        self._template = self.configuration

    def _write_to_file(self):
        if not os.path.isfile(self._config_template_path):
            raise FileNotFoundError("Invalid template file")

        with open(self._config_output, "w") as f:
            f.write(nginx_build(self._template["config"][0]["parsed"], header=True))
