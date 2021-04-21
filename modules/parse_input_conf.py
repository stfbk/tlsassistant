import json
from pathlib import Path
from utils.validation import Validator
from utils.loader import load_class
from os.path import sep
from utils.configuration import merge


class Parser:
    __cache = {}

    def __init__(self, to_parse: str):
        self.__input_dict = {}
        self.__output = []
        self.__configs_path = f"configs{sep}modules{sep}"
        self.__parse(to_parse)

    def remove(self, data, key, value):
        if key in data:
            if not value:  # value is empty or false, just remove it
                data.pop(key, None)  # delete
            elif isinstance(value, type(data[key])):  # if same type
                if isinstance(
                        value, list
                ):  # if it's a list, like modules
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
                    # print(data)
                    for key, value in included["remove"].items():
                        print(self.remove(data, key, value))
                    # print(data)
                    input()
                if "add" in included:
                    data = merge(data, included['add'])

                return data
            else:
                raise FileNotFoundError(f"File {path.absolute()} doesn't exists.")

    def __parse(self, to_parse):
        path = Path(to_parse)
        if not path.exists():
            raise FileNotFoundError("Configuration file not found.")
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

        for module in data["modules"]:
            module_path = Path(
                f"{self.__configs_path}{module}.json"
            )  # search for config file
            if not module_path.exists():
                raise FileNotFoundError(
                    f"Couldn't find the configuration file of the module {module_path.absolute()}"
                )
            with module_path.open() as mod_file:
                mod_data = json.load(mod_file)
                self.__cache[Path(mod_data["path"]).stem] = (
                    load_class(
                        mod_data["path"],
                        Path(mod_data["path"]).stem,
                        mod_data["class_name"],
                    ),
                    data["args"][module]
                    if "args" in data and module in data["args"]
                    else [],
                )
                # todo validazione input: args quali? tipizzati giusti? effettuarne il controllo preventivamente

    def output(self):
        return self.__cache
