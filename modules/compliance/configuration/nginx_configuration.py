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

    def add_configuration_for_field(self, field, field_rules, data, columns, guideline):
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
                                                columns, data, config_field, guideline)
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
            if " " in config_field:
                tokens = config_field.split(" ")
                config_field = tokens[0]
                for arg in tokens[1:]:
                    args.insert(0, arg)
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
            if name:
                for i, element in enumerate(directive["args"]):
                    if name in element:
                        directive["args"][i] = element.replace(name, "")
                        directive["args"][i] = re.sub("::*", ":", directive["args"][i])
                        found = True
            else:
                self._template["config"][0]["parsed"][1]["block"].remove(directive)

    def _load_template(self):
        self._load_conf(Path(self._config_template_path))
        self._template = self.configuration

    def _write_to_file(self):
        if not os.path.isfile(self._config_template_path):
            raise FileNotFoundError("Invalid template file")

        with open(self._config_output, "w") as f:
            f.write(nginx_build(self._template["config"][0]["parsed"], header=True))

    def get_conf_data(self, dictionary: dict):
        user_configuration = {}
        for directive in self.reverse_mapping:
            first_entry = ""
            name = self.reverse_mapping[directive]
            if " " in directive:
                tokens = directive.split(" ")
                directive = tokens[0]
                first_entry = tokens[1]
            if not user_configuration.get(name):
                user_configuration[name] = []
            for block in self.configuration["config"][0]["parsed"][1]["block"]:
                if first_entry and block.get("directive") == directive and block["args"][0] == first_entry:
                    user_configuration[name].extend(block["args"][1:])
                elif block.get("directive") == directive and not first_entry:
                    user_configuration[name].extend(block["args"])
        self._set_defaults(user_configuration)
        for directive in user_configuration:
            if directive == "Protocol":
                dictionary[directive] = {}
                protocols = user_configuration[directive]
                for protocol in protocols:
                    protocol = protocol.replace("v", " ")
                    dictionary[directive][protocol] = "!" not in protocol and "-" not in protocol
            elif directive in ["CipherSuites", "CipherSuitesTLS1.3"]:
                ciphers = user_configuration[directive][0]
                directive = "CipherSuite"
                if not dictionary.get(directive):
                    dictionary[directive] = []
                ciphers = self.prepare_ciphers(ciphers)
                dictionary[directive].extend(self.expand_ciphers(ciphers))
            elif directive == "Groups":
                groups = user_configuration[directive][0]
                dictionary[directive] = groups.split(":") if ":" in groups else [groups]
        dictionary["CipherSuite"] = set(dictionary["CipherSuite"])
