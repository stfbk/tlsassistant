from jsonmerge import Merger


def merge(base, head):
    merger = Merger(
        {
            "oneOf": [
                {"type": "array", "mergeStrategy": "append"},
                {"type": "object", "additionalProperties": {"$ref": "#"}},
                {"type": "string"},
                {"type": "number"},
            ]
        }
    )
    return merger.merge(base, head)