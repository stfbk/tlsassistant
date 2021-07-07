from utils.prune import pruner


def boolean_results(modules: list or dict, raw_results: dict) -> dict:
    b_res = {}
    res = pruner(raw_results)
    for module in modules:
        b_res[module] = True if module in res and res else False
    return b_res
