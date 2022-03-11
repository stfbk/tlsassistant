from enum import Enum
from pathlib import Path

from modules.configuration.configuration_base import Config_base
from utils.logger import Logger
from utils.validation import Validator
from crossplane import parse as nginx_parse
from apacheconfig import make_loader


class Configuration:
    """
    Apache/Nginx configuration file parser
    """

    class Type(Enum):
        """
        Enum for configuration file types
        """

        AUTO = 0
        APACHE = 1
        NGINX = 2

    def __init__(self, path: str, type_: Type = Type.AUTO, port=None):
        """
        :param path: path to the configuration file
        :type path: str
        :param type_: Type of the configuration file.
        :type type_: Type
        :param port: port to use for the check.
        :type port: str
        """
        Validator([(path, str), (type_, self.Type), (port if port else "", str)])
        self.__path = path
        self.__type = type_
        self.__port = port
        self.__logging = Logger("Configuration APACHE/NGINX")
        self.__loaded_conf = self.__load_conf(path)

    def get_path(self):
        return self.__path

    def __obtain_vhost(self, port=None):
        """
        Obtain the virtualhosts from the configuration file.

        :param port: port to use for the check.
        :type port: str
        :return: list of virtualhosts
        :rtype: list
        """
        assert self.__type != self.Type.AUTO, "Can't use this method with AUTO type."
        if self.__type == self.Type.APACHE:
            if "VirtualHost" not in self.__loaded_conf:
                self.__loaded_conf["VirtualHost"] = []
            loaded_vhost = self.__loaded_conf["VirtualHost"]
            # loaded_vhost è dict se solo uno presente, lista di dict altrimenti
            if isinstance(loaded_vhost, list):
                for vhost in loaded_vhost:
                    if not port or port in list(vhost.keys())[0]:
                        yield vhost
            else:
                if not port or port in list(loaded_vhost.keys())[0]:
                    yield loaded_vhost
        elif self.__type == self.Type.NGINX:
            raise NotImplementedError

    def __load_conf(self, path) -> dict:
        """
        Load the configuration file.

        :param path: path to the configuration file
        :type path: str
        :return: loaded configuration
        :rtype: dict
        """

        file = Path(path)
        assert (
            file.exists()
        ), f"Can't find the APACHE/NGINX file to parse at {file.absolute()}"
        if self.__type == self.Type.AUTO:
            try:
                results = self.__load_apache_conf(file)
                self.__type = self.Type.APACHE
            except Exception as e:
                self.__logging.debug(
                    f"Couldn't parse config as apache: {e}\ntrying with nginx..."
                )
                results = self.__load_nginx_conf(file)
                self.__type = self.Type.NGINX
        elif self.__type == self.Type.APACHE:
            results = self.__load_apache_conf(file)
        else:
            results = self.__load_nginx_conf(file)
        return results

    def __load_apache_conf(self, file: Path) -> dict:
        """
        Internal method to load the apache configuration file.

        :param file: path to the configuration file
        :type file: str
        :return: loaded configuration
        :rtype: dict
        """
        with make_loader() as loader:
            return loader.load(str(file.absolute()))

    def __load_nginx_conf(self, file: Path) -> dict:
        """
        Internal method to load the nginx configuration file.

        :param file: path to the configuration file
        :type file: str
        :return: loaded configuration
        :rtype: dict
        """
        return nginx_parse(str(file.absolute()))

    def __is_config_enabled(self, module) -> bool:
        """
        Checks if the module is enabled for the configuration analysis.

        :param module: module to check
        :type module: Module
        :return: True if the module is enabled
        :rtype: bool
        """
        return hasattr(module, "conf") and isinstance(module.conf, Config_base)

    def __check_global(self, modules: dict, openssl: str, ignore_openssl: bool):
        """
        Checks if the global configuration is vulnerable.

        :param modules: modules to check
        :type modules: dict
        :param openssl: openssl version to use
        :type openssl: str
        :param ignore_openssl: ignore openssl version
        :type ignore_openssl: bool
        :return: True if the configuration is vulnerable
        :rtype: dict
        """
        br = {"global": {}}
        for name, module in modules.items():
            if self.__is_config_enabled(module):
                self.__blackbox(
                    module,
                    name,
                    fix=False,
                    vhost=self.__loaded_conf,
                    vhost_name="global",
                    openssl=openssl,
                    ignore_openssl=ignore_openssl,
                    boolean_results=br,
                    global_value=None,
                )
        return br["global"]

    def __check_usage(self, module, vhost_name) -> bool:
        """
        Checks if the module is enabled for the configuration analysis.

        :param module: module to check
        :type module: Module
        :param vhost_name: name of the vhost
        :type vhost_name: str
        :return: True if the module is enabled
        :rtype: bool
        """
        if module.conf.VHOST_USE:
            return str(module.conf.VHOST_USE) in vhost_name
        else:
            return True

    def __vhost_wrapper(
            self,
            modules: dict,
            online=False,
            fix=False,
            openssl: str = None,
            ignore_openssl: bool = False,
    ):
        """
        Wrapper for the vhosts.

        :param modules: modules to check
        :type modules: dict
        :param online: check online
        :type online: bool
        :param fix: fix the configuration
        :type fix: bool
        :param openssl: openssl version to use
        :type openssl: str
        :param ignore_openssl: ignore openssl version
        :type ignore_openssl: bool
        :return: True if the configuration is vulnerable
        :rtype: dict
        """
        boolean_results = {}
        is_executed = False  # needed to check if the for loop is executed, and so the boolean_results are filled
        boolean_results_global = self.__check_global(modules, openssl, ignore_openssl)
        for virtualhost in self.__obtain_vhost(port=self.__port):
            for vhost_name, vhost in virtualhost.items():
                for name, module in modules.items():
                    if self.__is_config_enabled(module) and self.__check_usage(
                            module, vhost_name
                    ):
                        if not online:
                            self.__blackbox(
                                module,
                                name,
                                fix,
                                vhost,
                                vhost_name,
                                openssl,
                                ignore_openssl,
                                boolean_results,
                                global_value=boolean_results_global,
                            )
                        else:
                            self.__hybrid(module, name, vhost, vhost_name)
                        is_executed = True
                    else:
                        self.__logging.debug(
                            f"The module {name} isn't compatible. Skipping..."
                        )
        return boolean_results if is_executed else {'General rules': boolean_results_global}

    def __hybrid(self, module, name, vhost, vhost_name) -> dict:
        """
        Internal method to check the configuration hybrid.

        :param module: module to check
        :type module: Module
        :param name: name of the module
        :type name: str
        :param vhost: virtualhost to check
        :type vhost: dict
        :param vhost_name: name of the vhost
        :type vhost_name: str
        :return: dict with the changes
        :rtype: dict
        """
        self.__logging.debug(f"Fixing vulnerability {name} in vhost {vhost_name}..")
        return module.conf.fix(vhost)

    def __blackbox(
            self,
            module,
            name,
            fix,
            vhost,
            vhost_name,
            openssl,
            ignore_openssl,
            boolean_results,
            global_value,
    ):
        """
        Internal method to check the configuration blackbox.

        :param module: module to check
        :type module: Module
        :param name: name of the module
        :type name: str
        :param fix: fix the configuration
        :type fix: bool
        :param vhost: virtualhost to check
        :type vhost: dict
        :param vhost_name: name of the vhost
        :type vhost_name: str
        :param openssl: openssl version to use
        :type openssl: str
        :param ignore_openssl: ignore openssl version
        :type ignore_openssl: bool
        :param boolean_results: boolean results
        :type boolean_results: dict
        :param global_value: global boolean results
        :type global_value: dict
        :return: dict changes made and edit boolean results as pointer.
        :rtype: dict
        """
        self.__logging.debug(f"Analyzing vulnerability {name} in vhost {vhost_name}..")
        if vhost_name not in boolean_results:
            boolean_results[vhost_name] = {}
        is_empty = module.conf.is_empty(vhost)

        module_result = module.conf.condition(
            vhost, openssl=openssl, ignore_openssl=ignore_openssl
        )
        boolean_results[vhost_name][name] = (
            global_value[name]
            if is_empty and global_value is not None
            else module_result
        )
        mitigation_and_raw = {}
        module._set_mitigations(
            mitigation_and_raw, name, boolean_results[vhost_name][name]
        )  # add mitigation
        # todo: add what we edited

        if fix:
            if boolean_results[vhost_name][name]:
                mitigation_and_raw["difference"] = self.__hybrid(
                    module, name, vhost, vhost_name
                )
        boolean_results[vhost_name][name] = mitigation_and_raw.copy()

    def is_vuln(self, modules: dict, openssl=None, ignore_openssl=False):
        """
        Checks if the configuration is vulnerable.

        :param modules: modules to check
        :type modules: dict
        :param openssl: openssl version to use
        :type openssl: str
        :param ignore_openssl: ignore openssl version
        :type ignore_openssl: bool
        :return: True if the configuration is vulnerable
        :rtype: bool
        """
        self.__logging.info("Checking for vulnerabilities...")
        return self.__vhost_wrapper(
            modules, openssl=openssl, ignore_openssl=ignore_openssl
        )

    def fix(self, modules: dict, openssl=None, ignore_openssl=False, online=False):
        """
        Fixes the configuration.

        :param modules: modules to check
        :type modules: dict
        :param openssl: openssl version to use
        :type openssl: str
        :param ignore_openssl: ignore openssl version
        :type ignore_openssl: bool
        :param online: check online
        :type online: bool

        """
        self.__logging.info("Fixing vulnerabilities...")
        return self.__vhost_wrapper(
            modules,
            fix=True,
            openssl=openssl,
            ignore_openssl=ignore_openssl,
            online=online,
        )

    def save(self, file_name: str = None):
        """
        Saves the configuration.

        :param file_name: file name to save, if None, the input file name is used
        :type file_name: str
        :default file_name: None
        """
        self.__logging.info("Saving config file...")
        if not file_name:
            path = self.__path
        else:
            path = file_name
        file = Path(path)
        file.touch()

        options = {
            'namedblocks': False
        }
        with make_loader(**options) as loader:
            loader.dump(filepath=str(file.absolute()), dct=self.__loaded_conf)
        self.__logging.info(f"Saved configuration in file {file.absolute()}")
