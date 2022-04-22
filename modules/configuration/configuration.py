from pathlib import Path
from modules.configuration.configuration_base import Config_base
from utils.logger import Logger
from utils.type import WebserverType
from utils.validation import Validator
from apacheconfig import make_loader
from crossplane import parse as nginx_parse, build as nginx_build
import ast


class Configuration:
    """
    Apache/Nginx configuration file parser
    """

    def __init__(self, path: str, type_: WebserverType = WebserverType.AUTO, port=None):
        """
        :param path: path to the configuration file
        :type path: str
        :param type_: WebserverType of the configuration file.
        :type type_: WebserverType
        :param port: port to use for the check.
        :type port: str
        """
        Validator([(path, str), (type_, WebserverType), (port if port else "", str)])
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
        assert self.__type != WebserverType.AUTO, "Can't use this method with webserver AUTO type."
        if self.__type == WebserverType.APACHE:
            if "VirtualHost" not in self.__loaded_conf:
                self.__loaded_conf["VirtualHost"] = []
            loaded_vhost = self.__loaded_conf["VirtualHost"]
            # loaded_vhost is dict if there is only one vhost, list of dict otherwise
            if isinstance(loaded_vhost, list):
                for vhost in loaded_vhost:
                    if not port or port in list(vhost.keys())[0]:
                        yield vhost
            else:
                if not port or port in list(loaded_vhost.keys())[0]:
                    yield loaded_vhost
        elif self.__type == WebserverType.NGINX:
            def __gen(conf_server):
                for server in conf_server:
                    # In our custom structure, if list of lists then server block 
                    # contains more than one 'listen' directive
                    if any(isinstance(el, list) for el in server['listen']):
                        for _port in server['listen']:
                            # I assume that the first element of (sub)list is the port
                            if not port or port in _port[0]:
                                yield {_port[0]: server}
                    else:
                        if not port or port in server['listen'][0]:
                            yield {server['listen'][0]: server}

            for file, conf in self.__loaded_conf.items():
                if 'server' in conf:
                    yield from __gen(conf['server'])

                if 'http' in conf:
                    for http in conf['http']:
                        if 'server' in http:
                            yield from __gen(http['server'])
            

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

        if self.__type == WebserverType.AUTO:
            try:
                results = self.__load_apache_conf(file)
                self.__type = WebserverType.APACHE
            except Exception as e:
                self.__logging.debug(
                    f"Couldn't parse config as apache: {e}\ntrying with nginx..."
                )
                results = self.__load_nginx_conf(file)
                self.__type = WebserverType.NGINX
        elif self.__type == WebserverType.APACHE:
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

        def __structure(payload, struct):
            """
            Funzione ricorsiva per generare una struttura chiave:blocco.

            :param payload: output della libreria parsing nginx
            :type payload: list
            :param struct: modifica la reference a questo dict
            :type struct: dict
            """
            for directive in payload:
                directive_key = directive['directive']
                special = False

                if directive_key not in struct:
                    struct[directive_key] = []
                elif 'block' not in directive: 
                    # if this key already exists, but it's not the start of a subblock,
                    # then it's a list of lists, to indicate many directive with same key
                    # but distinct values
                    # Example: 
                    # {
                    #   listen 80;
                    #   listen 443 ssl;
                    # }
                    # will become
                    #   {'listen': [['80'], ['443', 'ssl']]}
                    if any(isinstance(el, str) for el in struct[directive_key]):
                        # first time I discover that there are more directive with same key,
                        # so I change the value of key to an array, and then I add what I have now in the loop
                        struct[directive_key] = [struct[directive_key], directive['args']]
                        special = True
                    elif any(isinstance(el, list) for el in struct[directive_key]):
                        struct[directive_key].append(directive['args'])
                        special = True

                if 'block' in directive:
                    struct[directive_key].append({})
                    index = len(struct[directive_key]) - 1

                    if len(directive['args']) != 0:
                        arg = repr(directive['args']) # list repr as argument of a block
                        struct[directive_key][index][arg] = {} # Subblock with key the arguments of a block, for example: location >>> = /50x.html <<< {...}
                        __structure(directive['block'], struct[directive_key][index][arg])
                    else:
                        __structure(directive['block'], struct[directive_key][index])
                elif not special: # if it's not a subblock and has not been already handled before
                    struct[directive_key] = directive['args']

        payload = nginx_parse(str(file.absolute()))
    
        if payload['status'] != 'ok' or len(payload['errors']) > 0:
            self.__logging.error(f"Error parsing nginx config: {payload['errors']}")
            raise Exception(f"Error parsing nginx config: {payload['errors']}")

        struct = {}
        for file in payload['config']:
            struct[file['file']] = {};
            __structure(file['parsed'], struct[file['file']])

            # Remove file if it doesn't have any 'http' or 'server' block
            # TODO: not robust enough, an include could be expanded with useful directive for us but not included at this point
            # ie: include snippet/directive/ssl.conf from https://github.com/risan/nginx-config
            if 'http' not in struct[file['file']] and 'server' not in struct[file['file']]:
                del struct[file['file']]

        return struct

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
                    vhost=self.__loaded_conf 
                            if self.__type == WebserverType.APACHE 
                            else next(val['http'][0] for file, val in self.__loaded_conf.items() if 'http' in val),
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
        
        module.conf.set_webserver(self.__type)

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

    def __rebuild(self, struct, my_payload):
        """
        Funzione ricorsiva per generare struttura dati utilizzata dalla libreria `crossplane`
        dalla nostra struttura custom
        
        :param struct: struttura dati custom creata dalla funzione `structure`
        :type struct: dict
        :param my_payload: output con modifica della reference a questa list
        :type my_payload: list
        """
        for key, val in struct.items():
            if type(val) == list:
                my_payload.append({})
                index = len(my_payload) - 1

                if len(val) > 0 and type(val[0]) == str: # args str
                    my_payload[index]['directive'] = key
                    my_payload[index]['args'] = val
                else: # first stage of subblock
                    max = len(val) - 1
                    for cont, v in enumerate(val):
                        if type(v) == list:
                            # Case where it's a list of lists as multiple directives with same key and different values
                            if len(v) > 0:
                                my_payload[index]['directive'] = key
                                my_payload[index]['args'] = v
                        else:
                            my_payload[index]['block'] = []
                            my_payload[index]['directive'] = key
                            # TODO: Evaluate use of eval to bring back args as list from a string
                            my_payload[index]['args'] = ast.literal_eval(*v) if any(isinstance(el, dict) for el in v.values()) else []
                            self.__rebuild(v, my_payload[index]['block'])

                        if cont < max: # If this is the last element of the subblock, don't add a new empty dict
                            my_payload.append({})
                            index = len(my_payload) - 1

            else: # special case where arg has a subblock: type(val) == dict
                # every entry is a new distinct block (see 'location' for reference)
                for k, v in val.items():
                    if any(isinstance(el, list) for el in v):
                        for entry in v:
                            my_payload.append({})
                            i = len(my_payload)-1

                            my_payload[i]['directive'] = k
                            my_payload[i]['args'] = entry
                    elif any(isinstance(el, dict) for el in v):
                        # this could be an 'if' directive, so let's start again with subblock
                        my_payload.append({})
                        i = len(my_payload)-1

                        my_payload[i]['directive'] = k
                        my_payload[i]['args'] = ast.literal_eval(*v[0].keys())
                        my_payload[i]['block'] = []
                        self.__rebuild(v[0], my_payload[i]['block'])
                    else:
                        my_payload.append({})
                        i = len(my_payload)-1

                        my_payload[i]['directive'] = k
                        my_payload[i]['args'] = v

    def __rebuild_wrapper(self, struct, my_payload):
        """
        Funzione wrapper per ritornare alla struttura della libreria 'crossplane' 
        dalla struttura personalizzata.

        :param struct: struttura dati custom creata dalla funzione `structure`
        :type struct: dict
        :param my_payload: output con modifica della reference a questa list
        :type my_payload: list
        """
        for key, val in struct.items():
            for entry in val:
                my_payload.append({})
                index = len(my_payload) - 1
                my_payload[index]['directive'] = key
                my_payload[index]['args'] = []
                if type(entry) == dict: # subblock incoming
                    my_payload[index]['block'] = []
                    self.__rebuild(entry, my_payload[index]['block'])
                elif type(entry) == list:
                    my_payload[index]['args'] = entry
                else:
                    my_payload[index]['args'] = val
                    break

    def save(self, file_path: str = None):
        """
        Saves the configuration.

        :param file_path: file name to save, if None, the input file name is used
        :type file_path: str
        :default file_path: None
        """
        self.__logging.info("Saving config file...")

        if self.__type == WebserverType.APACHE:
            if not file_path:
                path = self.__path
            else:
                path = file_path
            file = Path(path)
            file.touch()

            options = {
                'namedblocks': False
            }
            with make_loader(**options) as loader:
                loader.dump(filepath=str(file.absolute()), dct=self.__loaded_conf)
            self.__logging.info(f"Saved configuration in file {file.absolute()}")

        elif self.__type == WebserverType.NGINX:
            cwd = Path.cwd()

            self_path = Path(self.__path).resolve() # main file path
            file_path_resolved = None # output file path
            output_folder = None # output base folder
            if file_path:
                file_path_resolved = Path(file_path).resolve()
                if file_path_resolved == cwd.resolve():
                    # Check that --apply-fix argument is not the current directory
                    # TODO: Doesn't check ../* path
                    file_path_resolved = Path('./nginx.conf').resolve()
                output_folder = file_path_resolved.parent
                if output_folder == cwd:
                    # -f arg is directly a "single" path (ex: -f output) 
                    # -> folder and main file will have this name -> ./output/output is the ex-"nginx.conf"
                    output_folder = file_path_resolved

                if output_folder.exists():
                    if output_folder.is_dir():
                        self.__logging.warning(f"Folder '{output_folder.absolute()}/' already exists, overwriting files...")
                    elif output_folder.is_file():
                        self.__logging.error(f"{output_folder.absolute()} is a file, cannot overwrite it to folder...")
                        raise NotADirectoryError(f"{output_folder.absolute()} is a file, cannot overwrite it to folder...")
                else:
                    self.__logging.debug(f"Folder '{output_folder}/' is not here, creating at {output_folder.absolute()}/")
                    output_folder.mkdir(parents=True, exist_ok=True)
            

            for path, val in self.__loaded_conf.items():
                this_path = Path(path).resolve()
                file = this_path

                if file_path:
                    if len(self.__loaded_conf) == 1:
                        # only one output file, so filename is exactly file_path
                        file = file_path_resolved
                    else:
                        file_name_extension = this_path.stem + ''.join(this_path.suffixes)

                        if self_path == this_path:
                            # main file needs to be renamed
                            file_name_extension = file_path_resolved.name
                            file = output_folder / file_name_extension
                        else:
                            sub_folder = this_path.parent.relative_to(self_path.parent) # subtree relative from main file folder
                            file = output_folder / sub_folder / file_name_extension
                
                if not file.parent.exists():
                    self.__logging.debug(f"Folder '{file.parent}/' is not here, creating at {file.parent.absolute()}/")
                    file.parent.mkdir(parents=True, exist_ok=True) # Also here to create 'sub_folder'
                
                file.touch() # Create the file
                
                my_payload = []
                self.__rebuild_wrapper(val, my_payload)
                config = nginx_build(my_payload)
                # print(config)
                file.write_text(config)

                self.__logging.info(f"Saved configuration in file {file.absolute()}")

        else:
            raise NotImplementedError
