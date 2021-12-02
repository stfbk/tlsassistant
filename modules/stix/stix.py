from enum import Enum

from modules.stix.stix_base import Bundled
from stix2 import Grouping, Sighting, ObservedData, MemoryStore, Bundle
from utils.logger import Logger
from utils.validation import Validator
from itertools import chain


class Stix:
    """
    This class is used to create a STIX bundle for each module.
    """

    class Type(Enum):
        """
        Class used to indicate the type of STIX Analysis: Hosts or Modules.
        """
        HOSTS = 0
        MODULES = 1

    def __init__(self, type_of_analysis: Type):
        self.bundle = None
        self.__logger = Logger("STIX")
        self.type_of_analysis = self.Type(type_of_analysis)

    def __run_modules_report(self, module, loaded_module, list_of_hosts_or_paths: list):
        if self.__check_module(loaded_module):
            obs_data = None
            obs_data_to_group = []
            vuln, mitigates, coa = None, None, None
            for hostname_or_path in list_of_hosts_or_paths:
                self.__logger.debug(
                    f"Generating STIX for module: {module} - {hostname_or_path}"
                )
                obs_data, coa, mitigates, vuln = loaded_module.stix.sight_data(
                    hostname_or_path, obs_data if obs_data else None
                )
                # mitigates coa and vuln are the same everytime, so it's ok to overwrite them.
                obs_data_to_group.append(ObservedData(**obs_data))
            if list_of_hosts_or_paths:
                object_ref_group = [vuln, mitigates, coa]
                return (
                    Sighting(vuln, observed_data_refs=obs_data_to_group),
                    object_ref_group,
                    obs_data_to_group,
                )
            else:
                return Sighting(), None, None
        return None, None, None

    def __run_hosts_report(self, modules, hostname_or_path: str):
        self.__logger.info("Generating STIX for hosts...")
        to_group = []
        obs_data = None
        coa_to_add = []
        for module, loaded_module in modules.items():
            if self.__check_module(
                    loaded_module
            ):  # checks for STIX bundle wrapper class
                # if ok, then run and obtain
                self.__logger.debug(f"Generating STIX for module: {module}")

                obs_data, coa, mitigates, vuln = loaded_module.stix.sight_data(
                    hostname_or_path, obs_data if obs_data else None
                )
                data_to_group = [mitigates, vuln]
                coa_to_add.append(coa)
                to_group.append(data_to_group)
        object_ref_group = list(chain.from_iterable(to_group))
        print(object_ref_group)
        group = Grouping(
            name=f"Vulnerabilities",
            object_refs=object_ref_group,
            context=f"TLSA Analysis of {hostname_or_path}",
        )
        object_ref_group = list(chain(object_ref_group, coa_to_add))
        observed_data = ObservedData(**obs_data)
        sighting = Sighting(group, observed_data_refs=[observed_data])
        return sighting, group, object_ref_group, observed_data

    def run(self, **kwargs):
        type_of_analysis = self.type_of_analysis
        validate = Validator([(type_of_analysis, self.Type)])
        if type_of_analysis == Stix.Type.HOSTS:
            assert "hostname_or_path" in kwargs, "hostname_or_path is required"
            assert "modules" in kwargs, "modules is required"
            validate.dict(kwargs["modules"])
            validate.string(kwargs["hostname_or_path"])
            return self.__run_hosts_report(
                kwargs["modules"], kwargs["hostname_or_path"]
            )
        else:  # type_of_analysis == Stix.Type.MODULES
            assert "module" in kwargs, "module is required"
            assert "loaded_module" in kwargs, "loaded_module is required"
            assert "hostnames_or_paths" in kwargs, "hostnames_or_paths is required"
            validate.string(kwargs["module"])
            validate.list(kwargs["hostnames_or_paths"])
            return self.__run_modules_report(
                kwargs["module"], kwargs["loaded_module"], kwargs["hostnames_or_paths"]
            )

    def build(self, results: dict, modules: dict):
        res = []
        Validator([(results, dict), (modules, dict)])
        print(self.type_of_analysis)
        if self.type_of_analysis == Stix.Type.HOSTS:
            self.__logger.debug("STIX creations of hosts...")
            for host in results:
                self.__logger.debug(f"creating {host}...")
                # obtaining vuln module list:
                vulnerable_modules = {
                    k: modules[k] for k in results[host]
                }
                if vulnerable_modules:
                    sighting, group, object_refs, observed_data = self.run(
                        modules=vulnerable_modules, hostname_or_path=host
                    )
                    first_level = [sighting, group, observed_data]
                    res = list(chain(res, first_level, object_refs))
        else:
            self.__logger.debug("STIX creations of modules...")
            for module, loaded_module in modules.items():
                if module in results:
                    if results[module]["hosts"]:
                        self.__logger.debug(f"creating for {module}...")
                        sighting, object_refs, observed_data = self.run(
                            type_of_analysis=Stix.Type.MODULES,
                            module=module,
                            loaded_module=loaded_module,
                            hostnames_or_paths=results[module]["hosts"],
                        )
                        first_level = [sighting, observed_data]
                        res = list(chain(res, first_level, object_refs))
        self.__logger.debug(f"Saving locally bundle...")
        self.bundle = Bundle(*res, allow_custom=True)
        self.__logger.debug(f"Done.")
        return self

    def build_and_save(self, results: dict, modules: dict, path: str):
        return self.build(results, modules).save_to_file(path)

    def save_to_file(self, path: str):
        self.__save_bundle(self.bundle, path)
        return self

    def __save_bundle(self, bundle: Bundle, path: str):
        mem = MemoryStore()
        self.__logger.debug("Adding STIX bundle to memory store")
        mem.add(bundle)
        self.__logger.info(f"Saving STIX bundle to disk in {path}")
        mem.save_to_file(path)

    def __check_module(self, module) -> bool:
        """
        Checks if the module is enabled for the stix output.

        :param module: module to check
        :type module: Module

        :return: True if the module is enabled
        :rtype: bool
        """
        return hasattr(module, "stix") and isinstance(module.stix, Bundled)
