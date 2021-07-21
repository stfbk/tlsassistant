import json
from pathlib import Path
from utils.validation import Validator
from utils.loader import load_class, load_configuration
from os.path import sep
from utils.configuration import merge


class Parser:
    """
    Parse input conf file and return a dict with the following structure:
    {
        "name": "name of the project",
        "modules": [
            "module1",
            "module2",
            ...
        ],
        "args": {
            "module1": {
                "arg1": "value",
                "arg2": "value",
                ...
            },
            "module2": {
                "arg1": "value",
                "arg2": "value",
                ...
            },
            ...
        }
    }
    """

    __cache = {}

    def __init__(self, to_parse: str or list):
        """
        :param to_parse: path to the configuration file or list of paths
        :type to_parse: str or list
        """
        self.__input_dict = {}
        self.__output = []
        # self.__configs_path = f"configs{sep}modules{sep}"
        if isinstance(to_parse, str):
            self.__parse(to_parse)
        elif isinstance(to_parse, list):
            self.__get_modules({"modules": to_parse})
        else:
            raise NotImplementedError("Not yet implemented parsing method")

    def remove(self, data, key, value):
        """
        Removes a configuration from the input dict
        :param data: input dict
        :param key: key to remove
        :param value: value to recusively remove

        """
        if key in data:
            if not value:  # value is empty or false, just remove it
                data.pop(key, None)  # delete
            elif isinstance(value, type(data[key])):  # if same type
                if isinstance(value, list):  # if it's a list, like modules
                    data[key] = list(set(data[key]) - set(value))
                elif isinstance(
                    value, dict
                ):  # if it's a dict, difference of the keys and rebuild dict
                    for k, v in value.items():
                        data[key][k] = self.remove(data[key], k, v)
            else:
                raise TypeError(
                    f"Value of {key} is {type(value)} and"
                    f" the imported {key} is {type(data[key])}. Type mismatch."
                )
        return data[key]

    def validate_include(self, included):
        """
        Validates the included configuration file
        :param included: list of included file
        :type included: list
        :return: dict with the validated configuration
        :rtype: dict
        """
        if "file" not in included:
            raise AssertionError("Missing file in include statement")
        else:
            path = Path(included["file"])
            if path.exists():
                with path.open() as file:
                    data = json.load(file)
                    if "include" in data:
                        data = self.validate_include(data)
                if "remove" in included:  # removed
                    for key, value in included["remove"].items():
                        self.remove(data, key, value)
                if "add" in included:
                    for key, value in included[
                        "add"
                    ].items():  # needed to remove cloned data
                        self.remove(data, key, value)
                    data = merge(data, included["add"])

                return data
            else:
                raise FileNotFoundError(f"File {path.absolute()} doesn't exists.")

    def __parse(self, to_parse):
        """
        Parse the input file

        :param to_parse: path to the input file
        :type to_parse: str
        :raise: AssertionError if the input file is not valid
        """
        path = Path(to_parse)
        if not path.exists():
            raise FileNotFoundError(f"Configuration file {path.absolute()} not found.")
        else:
            with path.open() as file:
                data = json.load(file)

        if "name" not in data:
            raise AssertionError(f"Missing fundamental parameter: name")
        Validator(
            [
                (data["name"], str),
                (data["include"] if "include" in data else {}, dict),
                (data["modules"] if "modules" in data else [], list),
            ]
        )
        # Input parsing
        if "include" in data:
            name = data["name"]
            data = self.validate_include(data["include"])
            data["name"] = name
        elif "modules" not in data:
            raise AssertionError("No modules neither includes are defined.")

        if "args" in data:
            Validator().dict(data["args"])
        self.__get_modules(data)

    def __get_modules(self, data: dict):
        """
        Get the modules from the input dict

        :param data: input dict
        :type data: dict

        """

        v = Validator([(data["modules"], list)])
        for module in data["modules"]:
            mod_data = load_configuration(module)
            mod_path = Path(mod_data["path"])
            self.__cache[mod_path.stem] = (
                load_class(
                    mod_data["path"],
                    mod_path.stem,
                    mod_data["class_name"],
                ),
                data["args"][module]
                if "args" in data and module in data["args"]
                else {},
            )
            for mod_folder in [
                a.stem.lower() for a in mod_path.parents
            ]:  # check if parent folder is android
                if mod_folder == "android":  # to know if android or not
                    self.__cache[mod_path.stem][0].is_android = True

    def output(self):
        """
        Return the parsed configuration
        :return: parsed configuration
        :rtype: dict
        """
        return self.__cache
