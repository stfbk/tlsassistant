def pruner(data):
    """
    Prune the data to remove the data that is not needed.
    :param data: The data to be pruned.
    :type data: dict
    :return: The pruned data.
    :rtype: dict
    """
    new_data = {}
    for k, v in data.items():
        if isinstance(v, dict):
            v = pruner(v)
        if not v in ("", None, {}):
            new_data[k] = v
    return new_data
