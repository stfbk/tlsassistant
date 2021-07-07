def boolean_results(modules: list, raw_results: dict) -> dict:
    b_res = {}
    for module in modules:
        b_res[module] = False if module in raw_results and raw_results else True
    return b_res
