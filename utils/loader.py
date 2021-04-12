import importlib.util


def load_module(module_path: str, module_name: str) -> object:
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded
