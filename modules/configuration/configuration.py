from enum import Enum
from pathlib import Path

from modules.configuration.configuration_base import Config_base
from utils.logger import Logger
from utils.validation import Validator
from crossplane import parse as nginx_parse
from apacheconfig import make_loader


class Configuration:
    class Type(Enum):
        AUTO = 0
        APACHE = 1
        NGINX = 2

    def __init__(self, path: str, type_: Type = Type.AUTO):
        Validator([(path, str), (type_, self.Type)])
        self.__path = path
        self.__type = type_
        self.__logging = Logger("Configuration APACHE/NGINX")
        self.__loaded_conf = self.__load_conf(path)

    def __obtain_vhost(self):
        assert self.__type != self.Type.AUTO, "Can't use this method with AUTO type."
        if self.__type == self.Type.APACHE:
            if 'VirtualHost' not in self.__loaded_conf:
                self.__loaded_conf['VirtualHost'] = []
            for vhost in self.__loaded_conf['VirtualHost']:
                yield vhost
        elif self.__type == self.Type.NGINX:
            raise NotImplementedError

    def __load_conf(self, path) -> dict:
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
        with make_loader() as loader:
            return loader.load(str(file.absolute()))

    def __load_nginx_conf(self, file: Path) -> dict:
        return nginx_parse(str(file.absolute()))

    def __is_config_enabled(self, module) -> bool:
        return hasattr(module, "conf") and isinstance(module.conf, Config_base)

    def __wrapper(self, modules: dict, fix=False, openssl: str = None, ignore_openssl: bool = False):
        boolean_results = {}
        for name, module in modules.items():
            for virtualhost in self.__obtain_vhost():
                for vhost_name, vhost in virtualhost.items():
                    if self.__is_config_enabled(module):
                        self.__logging.debug(f"Analyzing vulnerability {name} in vhost {vhost_name}..")
                        if vhost_name not in boolean_results:
                            boolean_results[vhost_name] = {}
                        boolean_results[vhost_name][name] = module.conf.condition(vhost, openssl=openssl,
                                                                                  ignore_openssl=ignore_openssl)
                        if fix:
                            if boolean_results[vhost_name][name]:
                                self.__logging.debug(f"Fixing vulnerability {name} in vhost {vhost_name}..")
                                module.conf.fix(vhost)
                    else:
                        self.__logging.warning(
                            f"The module {name} isn't compatible. Skipping..."
                        )
        return boolean_results

    def is_vuln(self, modules: dict, openssl=None, ignore_openssl=False):
        self.__logging.info("Checking for vulnerabilities...")
        return self.__wrapper(modules, openssl=openssl, ignore_openssl=ignore_openssl)

    def fix(self, modules: dict, openssl=None, ignore_openssl=False):
        self.__logging.info("Fixing vulnerabilities...")
        return self.__wrapper(modules, fix=True, openssl=openssl, ignore_openssl=ignore_openssl)
