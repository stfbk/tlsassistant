# imports
from jinja2 import FileSystemLoader, Environment
import datetime
import random
import argparse

# parse inputs
parser = argparse.ArgumentParser()
parser.add_argument(
    "-f",
    "--file",
    help="file to render",
    choices=["hosts_report.html", "modules_report.html"],
    required=True,
)
# list of modules
parser.add_argument(
    "-m",
    "--modules",
    help="list of modules to import",
    nargs="+",
    type=str,
    required=True,
)
# list of hosts
parser.add_argument(
    "-s", "--hosts", help="list of hosts to import", nargs="+", type=str, required=True
)

args = parser.parse_args()

env = Environment(loader=FileSystemLoader("../configs/out_template/"))

template = env.get_template(args.file)

from json import load

m_dict = {}


class CaseInsensitiveDict(dict):
    @classmethod
    def _k(cls, key):
        return key.lower()

    def __init__(self, *args, **kwargs):
        super(CaseInsensitiveDict, self).__init__(*args, **kwargs)
        self._convert_keys()

    def __getitem__(self, key):
        return super(CaseInsensitiveDict, self).__getitem__(self.__class__._k(key))

    def __setitem__(self, key, value):
        super(CaseInsensitiveDict, self).__setitem__(self.__class__._k(key), value)

    def __delitem__(self, key):
        return super(CaseInsensitiveDict, self).__delitem__(self.__class__._k(key))

    def __contains__(self, key):
        return super(CaseInsensitiveDict, self).__contains__(self.__class__._k(key))

    def has_key(self, key):
        return super(CaseInsensitiveDict, self).has_key(self.__class__._k(key))

    def pop(self, key, *args, **kwargs):
        return super(CaseInsensitiveDict, self).pop(
            self.__class__._k(key), *args, **kwargs
        )

    def get(self, key, *args, **kwargs):
        return super(CaseInsensitiveDict, self).get(
            self.__class__._k(key), *args, **kwargs
        )

    def setdefault(self, key, *args, **kwargs):
        return super(CaseInsensitiveDict, self).setdefault(
            self.__class__._k(key), *args, **kwargs
        )

    def update(self, E={}, **F):
        super(CaseInsensitiveDict, self).update(self.__class__(E))
        super(CaseInsensitiveDict, self).update(self.__class__(**F))

    def _convert_keys(self):
        for k in list(self.keys()):
            v = super(CaseInsensitiveDict, self).pop(k)
            self.__setitem__(k, v)


for module in args.modules:
    with open("../configs/mitigations/" + module.upper() + ".json") as f:
        data = CaseInsensitiveDict(load(f))
        m_dict[module] = CaseInsensitiveDict(data["Entry"])
print(m_dict)

results = {}
if args.file == "hosts_report.html":
    for host in args.hosts:
        results[host] = {}
        for module in args.modules:
            # choose randomly if the module is in the list
            if random.randint(0, 1) == 1:
                results[host][module] = m_dict[module]
        # if no modules, delete the host
        if not results[host]:
            del results[host]
else:
    for module in args.modules:
        results[module] = m_dict[module]
        results[module]["hosts"] = []
        for host in args.hosts:
            # choose randomly if the host is in the list
            if random.randint(0, 1) == 1:
                results[module]["hosts"].append(host)
        # if no host, delete the module from the results
        if not results[module]["hosts"]:
            del results[module]

print(results)

with open("../outtest.html", "w") as f:
    f.write(
        template.render(
            date=datetime.datetime.now(),
            version="1.2.2 closed beta",
            modules=args.modules,
            results=results,
        )
    )
