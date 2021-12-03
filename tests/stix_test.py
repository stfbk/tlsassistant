from modules.server.mitzvah import Mitzvah
from modules.server.lucky13 import Lucky13
from modules.server.robot import Robot
from modules.stix.stix import Stix

hosts = ["a", "b", "c"]
res = []
from itertools import chain

modules = {"mitzvah": Mitzvah(), "lucky13": Lucky13(), "Robot": Robot()}
for host in hosts:
    sighting, group, object_refs, observed_data = Stix().run(
        modules=modules, hostname_or_path=host
    )
    first_level = [sighting, group, observed_data]
    res = list(chain(res, first_level, object_refs))
res_modules = []
for module, loaded_module in modules.items():
    sighting, object_refs, observed_data = Stix().run(
        type_of_analysis=Stix.Type.MODULES,
        module=module,
        loaded_module=loaded_module,
        hostnames_or_paths=hosts,
    )
    first_level = [sighting, observed_data]
    res_modules = list(chain(res_modules, first_level, object_refs))
from stix2 import Bundle
from pprint import pprint

b = Bundle(*res, allow_custom=True)
b_modules = Bundle(*res_modules, allow_custom=True)

from stix2 import MemoryStore

mem = MemoryStore()
mem.add(b)
mem.save_to_file("out.json")
mem = MemoryStore()
mem.add(b_modules)
mem.save_to_file("out_modules.json")
