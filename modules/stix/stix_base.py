from stix2 import Vulnerability, CourseOfAction, Relationship
from stix2 import URL
from stix2 import IPv4Address
from utils.validation import Validator
from datetime import datetime
from utils.urls import validate_ip
from utils.logger import Logger


class Bundled:
    """
    This class will generate the bundle for the STIX2 objects dinamically from the mitigation.
    """

    # Creation of COA
    def __coa(self, mitigation_object: dict, args=None):
        """
        This method will create the course of action object.

        :param mitigation_object: The mitigation object
        :type mitigation_object: dict
        :param args: The arguments
        :type args: dict

        :return: The course of action object
        :rtype: stix2.CourseOfAction
        """
        if args is None:
            args = {}
        mitigation = self.__clean_mitigation(mitigation_object)
        assert "Name" in mitigation, "'name' in mitigation is required!"
        name = mitigation["Name"]
        if "Mitigation" in mitigation:
            description = (
                mitigation["Mitigation"]["Textual"]
                if "Textual" in mitigation["Mitigation"]
                else ""
            )
            x_mitigation_apache = (
                mitigation["Mitigation"]["Apache"]
                if "Apache" in mitigation["Mitigation"]
                else ""
            )
            x_mitigation_nginx = (
                mitigation["Mitigation"]["nginx"]
                if "nginx" in mitigation["Mitigation"]
                else ""
            )
        else:
            description = ""
            x_mitigation_apache = ""
            x_mitigation_nginx = ""

        args["type"] = "course-of-action"
        args["name"] = name
        if description:
            args["description"] = description
        if x_mitigation_apache:
            args["x_mitigation_apache"] = x_mitigation_apache
        if x_mitigation_nginx:
            args["x_mitigation_nginx"] = x_mitigation_nginx

        args["allow_custom"] = True
        self.__logger.debug("Creating the course of action object...")
        return CourseOfAction(**args)

    # Creation of the observed data
    def __observed_data(self, url, args=None):
        """
        This method will create the observed data object.

        :param url: The URL
        :type url: str
        :param args: The arguments
        :type args: dict

        :return: The observed data args
        :rtype: args
        """
        if args is None:
            args = {}
        timestamp = datetime.now()
        args["first_observed"] = (
            args["first_observed"] if "first_observed" in args else timestamp
        )
        args["last_observed"] = timestamp
        args["number_observed"] = (
            args["number_observed"] + 1 if "number_observed" in args else 1
        )
        args["objects"] = {
            0: (URL(value=url) if not validate_ip(url) else IPv4Address(value=url))
        }
        self.__logger.debug("Creating the observed data object...")
        return args

    def __clean_mitigation(self, mitigation_object: dict):
        if "Entry" in mitigation_object:
            mitigation = mitigation_object["Entry"].copy()
        else:
            mitigation = mitigation_object.copy()
        return mitigation

    # Creation of the vulnerability object
    def __vulnerability(self, mitigation_object: dict, args=None):
        """
        This method will create the vulnerability object.

        :param args: The arguments
        :type args: dict

        :return: The vulnerability object
        :rtype: stix2.Vulnerability
        """
        if args is None:
            args = {}
        mitigation = self.__clean_mitigation(mitigation_object)
        assert "Name" in mitigation, "'Name' in vulnerability is required!"
        assert (
            "Description" in mitigation
        ), "'Description' in vulnerability is required!"
        Validator([(mitigation["Name"], str), (mitigation["Description"], str)])
        args["type"] = "vulnerability"
        args["name"] = mitigation["Name"]
        args["description"] = mitigation["Description"]
        self.__logger.debug(f"Creating the vulnerability object for {args['name']}...")
        return Vulnerability(**args)

    def __init__(
        self,
        mitigation_object: dict,
        vuln_args=None,
        coa_args=None,
    ):
        """
        This class will generate the bundle for the STIX2 objects dinamically from the mitigation.
        The init method will initialize the object with the required parameters.

        :param mitigation_object: The mitigation object
        :type mitigation_object: dict
        :param vuln_args: The vulnerability arguments
        :type vuln_args: dict
        :param obs_args: The observed data arguments
        :type obs_args: dict
        :param coa_args: The course of action arguments
        :type coa_args: dict

        """
        if coa_args is None:
            coa_args = {}
        if vuln_args is None:
            vuln_args = {}

        Validator(
            [
                (mitigation_object, dict),
                (vuln_args, dict),
                (coa_args, dict),
            ]
        )
        self.vuln = vuln_args
        self.__logger = Logger("Bundled")
        self.coa_data = coa_args
        self.mitigation_object = mitigation_object

    def sight_data(self, url: str, observable_data: dict):
        # return the data necessary to build the bundle externally, by adding other bundles
        ob_data = self.__observed_data(url, observable_data)

        vuln = self.__vulnerability(self.mitigation_object, self.vuln)
        coa = self.__coa(self.mitigation_object, self.coa_data)
        mitigates = Relationship(
            source_ref=coa, target_ref=vuln, relationship_type="mitigates"
        )

        return ob_data, coa, mitigates, vuln
