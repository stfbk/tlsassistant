from modules.stix.stix_base import Bundled
from stix2 import Grouping, Sighting, ObservedData
from utils.logger import Logger
from utils.validation import Validator
from itertools import chain


class Stix:
    """
    This class is used to create a STIX bundle for each module.
    """

    def __init__(self):
        self.__logger = Logger("STIX")

    def run(self, modules, hostname_or_path: str):
        self.__logger.info("Generating STIX for modules...")
        Validator([(modules, dict)])
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
        group = Grouping(
            name=f"TLSA Analysis",
            object_refs=object_ref_group,
            context=f"TLSA Analysis of {hostname_or_path}",
        )
        object_ref_group = list(chain(object_ref_group, coa_to_add))
        observed_data = ObservedData(**obs_data)
        sighting = Sighting(group, observed_data_refs=[observed_data])
        return sighting, group, object_ref_group, observed_data

    def __check_module(self, module) -> bool:
        """
        Checks if the module is enabled for the stix output.

        :param module: module to check
        :type module: Module

        :return: True if the module is enabled
        :rtype: bool
        """
        return hasattr(module, "stix") and isinstance(module.stix, Bundled)
