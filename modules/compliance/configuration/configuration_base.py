from pathlib import Path

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

    def configuration_output(self):
        self._write_to_file()
        return self._output_dict.copy()
