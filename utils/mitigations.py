import json
import logging
from pathlib import Path
from os.path import sep


def load_mitigation(mitigation_name: str, raise_error=False, force=False) -> dict:
    """
    Wrapper for mitigation loader.

    :param mitigation_name: The object to type check
    :param raise_error: Raise the error if any.
    :type raise_error: bool
    :param force: Force the analysis and ingore the cache
    :type force: bool
    :return: Dict of the mitigation if present, empty dict or raise error if not
    :rtype: dict
    :raise FileNotFoundError: If mitigation not found
    """
    return MitigationLoader().load_mitigation(mitigation_name, raise_error, force)


class MitigationLoader:
    __cache = {}

    def load_mitigation(
        self, mitigation_name: str, raise_error=True, force=False
    ) -> dict:
        """
        Load the mitigation and return the dict of the mitigation loaded

        :param mitigation_name: The object to type check
        :param raise_error: Raise the error if any.
        :type raise_error: bool
        :param force: Force the analysis and ingore the cache
        :type force: bool
        :return: Dict of the mitigation if present, empty dict or raise error if not
        :rtype: dict
        :raise FileNotFoundError: If mitigation not found
        """
        mitigation_name = mitigation_name.replace(" ", "_")
        mitigation_name = mitigation_name.upper()
        mitigation_path = Path(f"configs{sep}mitigations{sep}{mitigation_name}.json")
        #print(mitigation_path)
        if not mitigation_path.exists():
            if raise_error:
                raise FileNotFoundError(
                    f"Mitigation file missing at {mitigation_path.absolute()}"
                )
            else:
                logging.warning(
                    f"Mitigation file missing at {mitigation_path.absolute()}, returning empty dict."
                )
                return {}
        if force:
            with mitigation_path.open() as file:
                mitigation_data = json.load(file)
                self.__cache[mitigation_name] = mitigation_data.copy()
        else:
            if mitigation_name in self.__cache:
                mitigation_data = self.__cache[mitigation_name].copy()
            else:
                mitigation_data = self.load_mitigation(
                    mitigation_name, raise_error, force=True
                )

        return mitigation_data
