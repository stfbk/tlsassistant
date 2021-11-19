import json
import logging
from pathlib import Path
from os.path import sep


def load_mitigation(mitigation_name: str, raise_error=True) -> dict:
    """
    Load the mitigation and return the dict of the mitigation loaded

    :param mitigation_name: The object to type check
    :param raise_error: Raise the error if any.
    :type raise_error: bool
    :return: Dict of the mitigation if present, empty dict or raise error if not
    :rtype: dict
    :raise FileNotFoundError: If mitigation not found
    """
    mitigation_name = mitigation_name.replace(" ", "_")
    mitigation_name = mitigation_name.upper()
    mitigation_path = Path(f"configs{sep}mitigations{sep}{mitigation_name}.json")
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
    with mitigation_path.open() as file:
        mitigation_data = json.load(file)
    return mitigation_data
