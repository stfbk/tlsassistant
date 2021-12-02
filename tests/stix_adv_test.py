from modules.server.mitzvah import Mitzvah
from modules.server.lucky13 import Lucky13
from modules.server.robot import Robot
from modules.stix.stix import Stix

hosts = ["a", "b", "c"]
modules = {"mitzvah": Mitzvah(), "lucky13": Lucky13(), "Robot": Robot()}
hostnames_analysis = Stix(type_of_analysis=Stix.Type.HOSTS)
modules_analysis = Stix(type_of_analysis=Stix.Type.MODULES)

hostnames_analysis.build_and_save(
    modules=modules, hostnames_or_paths=hosts, path="out.json"
)
modules_analysis.build_and_save(
    modules=modules, hostnames_or_paths=hosts, path="out_modules.json"
)
