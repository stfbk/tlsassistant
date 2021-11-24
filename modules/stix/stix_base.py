from stix2 import Vulnerability, CourseOfAction, Relationship, Bundle
from stix2 import Sighting
from stix2 import ObservedData
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
        if 'Entry' in mitigation_object:
            mitigation = mitigation_object['Entry'].copy()
        else:
            mitigation = mitigation_object.copy()
        assert 'Name' in mitigation, "'name' in mitigation is required!"
        name = mitigation['Name']
        if 'Mitigation' in mitigation:
            description = mitigation['Mitigation']['Textual'] if 'Textual' in mitigation['Mitigation'] else ''
            x_mitigation_apache = mitigation['Mitigation']['Apache'] if 'Apache' in mitigation['Mitigation'] else ''
            x_mitigation_nginx = mitigation['Mitigation']['Nginx'] if 'Nginx' in mitigation['Mitigation'] else ''
        else:
            description = ''
            x_mitigation_apache = ''
            x_mitigation_nginx = ''

        args['type'] = 'course-of-action'
        args['name'] = name
        if description:
            args['description'] = description
        if x_mitigation_apache:
            args['x_mitigation_apache'] = x_mitigation_apache
        if x_mitigation_nginx:
            args['x_mitigation_nginx'] = x_mitigation_nginx

        args['allow_custom'] = True
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

        :return: The observed data object
        :rtype: stix2.ObservedData
        """
        if args is None:
            args = {}
        timestamp = datetime.now()
        args['first_observed'] = args['first_observed'] if 'first_observed' in args else timestamp
        args['last_observed'] = timestamp
        args['number_observed'] = args['number_observed'] + 1 if 'number_observed' in args else 1
        args['objects'] = {0: (URL(value=url) if not validate_ip(url) else IPv4Address(value=url))}
        self.__logger.debug("Creating the observed data object...")
        return ObservedData(**args)

    # Creation of the vulnerability object
    def __vulnerability(self, args=None):
        """
        This method will create the vulnerability object.

        :param args: The arguments
        :type args: dict

        :return: The vulnerability object
        :rtype: stix2.Vulnerability
        """
        if args is None:
            args = {}
        assert 'name' in args, "'name' in vulnerability is required!"
        assert 'description' in args, "'description' in vulnerability is required!"
        Validator(
            [
                (args['name'], str),
                (args['description'], str)
            ]
        )
        args['type'] = 'vulnerability'
        self.__logger.debug(f"Creating the vulnerability object for {args['name']}...")
        return Vulnerability(**args)

    def __init__(self, hostname: str, mitigation_object: dict, vuln_args: dict, obs_args: dict, coa_args: dict):
        """
        This class will generate the bundle for the STIX2 objects dinamically from the mitigation.
        The init method will initialize the object with the required parameters.

        :param hostname: The hostname of the target
        :type hostname: str
        :param mitigation_object: The mitigation object
        :type mitigation_object: dict
        :param vuln_args: The vulnerability arguments
        :type vuln_args: dict
        :param obs_args: The observed data arguments
        :type obs_args: dict
        :param coa_args: The course of action arguments
        :type coa_args: dict

        """
        Validator(
            [
                (hostname, str),
                (mitigation_object, dict),
                (vuln_args, dict),
                (obs_args, dict),
                (coa_args, dict)
            ]
        )
        self.vuln = vuln_args
        self.__logger = Logger("Bundled")
        self.obs_data = obs_args
        self.coa_data = coa_args
        self.hostname = hostname
        self.mitigation_object = mitigation_object

    def obtain_bundle_data(self):
        # return the data necessary to build the bundle externally, by adding other bundles
        pass

    def build(self) -> Bundle:
        """
        Method that will build the bundle.

        :return: The bundle
        :rtype: stix2.Bundle
        """
        self.__logger.debug("Building the bundle...")
        vuln = self.__vulnerability(**self.vuln)
        sight = Sighting(vuln,
                         observed_data_refs=[self.__observed_data(**self.obs_data)])
        coa = CourseOfAction(**self.coa_data)
        self.__logger.debug("Creating the Relationship object...")
        mitigates = Relationship(coa, 'mitigates', vuln)
        self.__logger.debug("Creating the Bundle object...")
        return Bundle(coa, mitigates, vuln, sight)
