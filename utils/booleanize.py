from utils.prune import pruner


def boolean_results(modules: list or dict, raw_results: dict) -> dict:
    """
    Booleanize the results of one or more modules.
    :param modules: list of modules to be booleanized
    :type modules: list
    :param raw_results: dictionary of raw results
    :type raw_results: dict
    :return: dictionary of booleanized results
    :rtype: dict
    """
    b_res = {}
    res = pruner(raw_results)
    for module in modules:
        b_res[module] = True if module in res and res else False
    return b_res


def boolean_results_hosts(modules: list or dict, raw_results: dict) -> dict:
    """
    Booleanize the results of one or more modules.
    :param modules: list of modules to be booleanized
    :type modules: list
    :param raw_results: dictionary of raw results
    :type raw_results: dict
    :return: dictionary of booleanized results
    :rtype: dict
    """
    b_res = {}
    res = pruner(raw_results)
    for host in raw_results:
        b_res[host] = {}
        for module in modules:
            b_res[host][module] = True if module in res[host] and res[host] else False
    return b_res


def boolean_results_modules(raw_results: dict) -> dict:
    """
    Booleanize the results of one or more modules.
    :param raw_results: dictionary of raw results
    :type raw_results: dict
    :return: dictionary of booleanized results
    :rtype: dict
    """
    b_res = {}
    res = pruner(raw_results)
    for module in raw_results:
        b_res[module] = {}
        for host in raw_results[module]:
            b_res[module][host] = True if module in res[host] and res[host] else False
    return b_res
