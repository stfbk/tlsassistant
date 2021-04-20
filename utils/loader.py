import importlib.util
from pydoc import locate


def load_module(module_path: str, module_name: str) -> object:
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def load_class(module_path: str, module_name: str, class_name: str) -> object:
    return getattr(load_module(module_path, module_name), class_name)


def obtain_type(type_):
    return locate(type_)
