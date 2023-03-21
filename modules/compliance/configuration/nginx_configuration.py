from pathlib import Path

from crossplane import parse as nginx_parse

from modules.compliance.configuration.configuration_base import ConfigurationMaker


class NginxConfiguration(ConfigurationMaker):
    def __init__(self, file: Path = None):
        super().__init__("nginx")
        if file:
            self.__load_conf(file)

    # Stole this function from Configuration for testing purposes
    def __load_conf(self, file: Path):
        """
        Internal method to load the nginx configuration file.

        :param file: path to the configuration file
        :type file: str
        """
        self.configuration = nginx_parse(str(file.absolute()))

    def add_configuration_for_field(self, field, field_rules, data, name_index, level_index):
        config_field = self.mapping.get(field, None)
        self._output_dict[field] = {}
        if not config_field:
            # This field isn't available with this configuration
            return
        tmp_string = "\t" + config_field + " "
        field_rules = self._specific_rules.get(field, field_rules)
        # the idea is that it is possible to define a custom value to insert like on/off or name to use the name
        # defined in the config file
        allow_string = field_rules.get("enable", "name")
        deny_string = field_rules.get("disable", "-name")
        separator = field_rules.get("separator", " ")
        # This parameter is needed to avoid having separators even if nothing gets added to deny (like ciphersuites)
        added_negatives = field_rules.get("added_negatives", False)
        replacements = field_rules.get("replacements", [])
        for entry in data:
            added = True
            name = entry[name_index]
            for replacement in replacements:
                name = name.replace(replacement, replacements[replacement])
            if entry[level_index] in ["must", "recommended"]:
                tmp_string += allow_string.replace("name", name)
                self._output_dict[field][name] = True
            elif entry[level_index] in ["must not", "not recommended"]:
                tmp_string += deny_string.replace("name", name)
                added = added_negatives
                self._output_dict[field][name] = False
            else:
                added = False
                self._output_dict[field][name] = False

            if added:
                tmp_string += separator

        if tmp_string and tmp_string[-1] == ":":
            tmp_string = tmp_string[:-1]
        if len(tmp_string) != len(config_field) + 1:  # this is to prevent adding a field without any value
            self._string_to_add += "\n" + tmp_string

    def write_to_file(self):
        """
        Loads the template, adds the new text and writes the result to the output_file.
        This one will also add a final "}" so that user doesn't need to move all the directives inside the server block.
        :return: a dictionary containing a report of what was added and what not
        """
        with open(self._config_output, "w") as f:
            f.write(self._load_template() + "\n" + self._string_to_add + "}")
        return self._output_dict.copy()
