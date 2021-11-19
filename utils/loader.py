import importlib.util
import json
from os.path import sep
from pathlib import Path
from pydoc import locate

from utils.urls import link_sep, url_domain
from utils.validation import Validator


def difference(modules: list, modules_to_exclude: list) -> list:
    """
    Return the difference between two lists.
    :param modules: modules to check
    :type modules: list
    :param modules_to_exclude: modules to exclude
    :type modules_to_exclude: list
    :return: list of modules
    :rtype: list
    """
    diff = list(set(map(str.lower, modules)) - set(map(str.lower, modules_to_exclude)))
    return diff


def load_module(module_path: str, module_name: str) -> object:
    """
    Load the module given. Do not use this. Use :func `load_class`: instead.

    :param module_path: path of the python module to load.
    :type module_path: str
    :param module_name: module name to load.
    :type module_name:str
    :return: Module loaded.
    :rtype obj:
    """
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def load_class(module_path: str, module_name: str, class_name: str) -> object:
    """
    Load the class module given.

    :param module_path: path of the python module to load.
    :type module_path: str
    :param module_name: module name to load.
    :type module_name:str
    :param class_name: path of the python module to load.
    :type module_name:str
    :return: Module class loaded.
    :rtype obj:
    """
    return getattr(load_module(module_path, module_name), class_name)


def obtain_type(type_: str):
    """
    From string to type.

    :param type_: the type in string.
    :type type_: str
    :return: Type.
    """
    return locate(type_)


def load_configuration(module: str, configs_path=None) -> dict:
    """
    Load the configuration and return the dict of the configuration loaded

    :param module: The module name to load the configuration.
    :type module: str
    :param configs_path: path where to check configs. Default `configs/modules/`
    :type configs_path: str
    :return: Dict of the configuration if present.
    :rtype: dict
    :raise FileNotFoundError: If configuration file not found
    """
    Validator().string(module)
    module = module.lower()
    if configs_path:
        module_path = Path(f"{configs_path}{module}.json")  # search for config file
        if not module_path.exists():
            raise FileNotFoundError(
                f"Couldn't find the configuration file of the module {module_path.absolute()}"
            )
    else:

        server_path = Path(
            f"configs{sep}modules{sep}server{sep}{module}.json"
        )  # search for config file in server
        android_path = Path(
            f"configs{sep}modules{sep}android{sep}{module}.json"
        )  # search for config file in android

        if server_path.exists():
            module_path = server_path
        elif android_path.exists():
            module_path = android_path
        else:
            raise FileNotFoundError(
                f"Couldn't find the configuration file of the module {module}.json"
            )

    with module_path.open() as mod_file:
        mod_data = json.load(mod_file)
    return mod_data


def load_list_of_domains(path: str) -> [str]:
    """
    Load a list of domains from a file.
    :param path: path of the file.
    :type path: str
    :return: list of domains.
    :rtype: list
    """
    file = Path(path)
    urls = []
    assert file.exists(), f"Path {file.absolute()} not found."
    with file.open() as f:
        for line in f:
            url, port = link_sep(line)
            urls.append(f"{url_domain(url)}:{port}")
    return urls
