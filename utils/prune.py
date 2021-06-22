def pruner(data):
    new_data = {}
    for k, v in data.items():
        if isinstance(v, dict):
            v = pruner(v)
        if not v in (u"", None, {}):
            new_data[k] = v
    return new_data
