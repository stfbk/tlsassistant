import importlib.util
import json
from os.path import sep
from pathlib import Path
from pydoc import locate

from utils.validation import Validator


def load_module(module_path: str, module_name: str) -> object:
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def load_class(module_path: str, module_name: str, class_name: str) -> object:
    return getattr(load_module(module_path, module_name), class_name)


def obtain_type(type_):
    return locate(type_)


def load_configuration(module: str, configs_path=f"configs{sep}modules{sep}"):
    Validator().string(module)
    module_path = Path(f"{configs_path}{module}.json")  # search for config file
    if not module_path.exists():
        raise FileNotFoundError(
            f"Couldn't find the configuration file of the module {module_path.absolute()}"
        )
    with module_path.open() as mod_file:
        mod_data = json.load(mod_file)
    return mod_data
