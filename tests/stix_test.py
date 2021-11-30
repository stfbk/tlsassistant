from modules.server.mitzvah import Mitzvah

from modules.stix.stix import Stix

hosts = ["a", "b", "c"]
res = []
from itertools import chain

for host in hosts:
    sighting, group, object_refs, observed_data = Stix().run(
        {"mitzvah": Mitzvah()}, host
    )
    first_level = [sighting, group, observed_data]
    res = list(chain(res, first_level, object_refs))
from stix2 import Bundle
from pprint import pprint

b = Bundle(*res, allow_custom=True)

from stix2 import MemoryStore

mem = MemoryStore()
mem.add(b)
mem.save_to_file("out.json")
