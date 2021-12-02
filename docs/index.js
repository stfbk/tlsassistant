URLS=[
"assets/index.html",
"configs/index.html",
"run.html",
"tlsa/index.html",
"tlsa/tlsa.html",
"utils/index.html",
"utils/loader.html",
"utils/logger.html",
"utils/validation.html",
"utils/prune.html",
"utils/counter.html",
"utils/configuration.html",
"utils/mitigations.html",
"utils/booleanize.html",
"utils/urls.html",
"utils/globals.html",
"utils/output.html",
"utils/colors.html",
"utils/subdomain_enumeration.html",
"modules/index.html",
"modules/stix/index.html",
"modules/stix/stix.html",
"modules/stix/stix_base.html",
"modules/android/index.html",
"modules/android/wrappers/index.html",
"modules/android/wrappers/mallodroid.html",
"modules/android/wrappers/super.html",
"modules/android/sslerror.html",
"modules/android/mallodroid_base.html",
"modules/android/obfuscated_code.html",
"modules/android/super_base.html",
"modules/android/trustmanager.html",
"modules/android/weak_algorithms.html",
"modules/android/hostnameverifier.html",
"modules/android/ssl_getinsecure_method.html",
"modules/android/webview_ssl_errors.html",
"modules/parse_input_conf.html",
"modules/server/index.html",
"modules/server/hsts_base.html",
"modules/server/wrappers/index.html",
"modules/server/wrappers/https_hsts.html",
"modules/server/wrappers/certificate.html",
"modules/server/wrappers/tlsfuzzer.html",
"modules/server/wrappers/testssl.html",
"modules/server/crime.html",
"modules/server/testssl_base.html",
"modules/server/logjam.html",
"modules/server/heartbleed.html",
"modules/server/drown.html",
"modules/server/pfs.html",
"modules/server/hsts_set.html",
"modules/server/three_shake.html",
"modules/server/renegotiation.html",
"modules/server/breach.html",
"modules/server/sweet32.html",
"modules/server/sloth.html",
"modules/server/tlsfuzzer_base.html",
"modules/server/ccs_injection.html",
"modules/server/nomore.html",
"modules/server/certificate_transparency.html",
"modules/server/https_enforced.html",
"modules/server/freak.html",
"modules/server/mitzvah.html",
"modules/server/hsts_preloading.html",
"modules/server/ticketbleed.html",
"modules/server/robot.html",
"modules/server/beast.html",
"modules/server/poodle.html",
"modules/server/lucky13.html",
"modules/core.html",
"modules/configuration/index.html",
"modules/configuration/configuration_base.html",
"modules/configuration/configuration.html",
"modules/report.html"
];
INDEX=[
{
"ref":"assets",
"url":0,
"doc":""
},
{
"ref":"configs",
"url":1,
"doc":""
},
{
"ref":"run",
"url":2,
"doc":""
},
{
"ref":"tlsa",
"url":3,
"doc":""
},
{
"ref":"tlsa.tlsa",
"url":4,
"doc":""
},
{
"ref":"tlsa.tlsa.Tlsa",
"url":4,
"doc":""
},
{
"ref":"utils",
"url":5,
"doc":""
},
{
"ref":"utils.loader",
"url":6,
"doc":""
},
{
"ref":"utils.loader.difference",
"url":6,
"doc":"Return the difference between two lists. :param modules: modules to check :type modules: list :param modules_to_exclude: modules to exclude :type modules_to_exclude: list :return: list of modules :rtype: list",
"func":1
},
{
"ref":"utils.loader.load_module",
"url":6,
"doc":"Load the module given. Do not use this. Use :func  load_class : instead. :param module_path: path of the python module to load. :type module_path: str :param module_name: module name to load. :type module_name:str :return: Module loaded. :rtype obj:",
"func":1
},
{
"ref":"utils.loader.load_class",
"url":6,
"doc":"Load the class module given. :param module_path: path of the python module to load. :type module_path: str :param module_name: module name to load. :type module_name:str :param class_name: path of the python module to load. :type module_name:str :return: Module class loaded. :rtype obj:",
"func":1
},
{
"ref":"utils.loader.obtain_type",
"url":6,
"doc":"From string to type. :param type_: the type in string. :type type_: str :return: Type.",
"func":1
},
{
"ref":"utils.loader.load_configuration",
"url":6,
"doc":"Load the configuration and return the dict of the configuration loaded :param module: The module name to load the configuration. :type module: str :param configs_path: path where to check configs. Default  configs/modules/ :type configs_path: str :return: Dict of the configuration if present. :rtype: dict :raise FileNotFoundError: If configuration file not found",
"func":1
},
{
"ref":"utils.loader.load_list_of_domains",
"url":6,
"doc":"Load a list of domains from a file. :param path: path of the file. :type path: str :return: list of domains. :rtype: list",
"func":1
},
{
"ref":"utils.logger",
"url":7,
"doc":""
},
{
"ref":"utils.logger.Logger",
"url":7,
"doc":"Logger to log errors and other messages :param obj: Obj (automatically gets type name) or name as a string. :type obj: str or obj :raise TypeError: If string or obj different"
},
{
"ref":"utils.logger.Logger.debug",
"url":7,
"doc":"Prints debug message. :param string: The string message. :type string: str",
"func":1
},
{
"ref":"utils.logger.Logger.warning",
"url":7,
"doc":"Prints warn message. :param string: The string message. :type string: str",
"func":1
},
{
"ref":"utils.logger.Logger.info",
"url":7,
"doc":"Prints info message. :param string: The string message. :type string: str",
"func":1
},
{
"ref":"utils.logger.Logger.error",
"url":7,
"doc":"Prints error message. :param string: The string message. :type string: str",
"func":1
},
{
"ref":"utils.validation",
"url":8,
"doc":""
},
{
"ref":"utils.validation.rec_search_key",
"url":8,
"doc":"Search a key in a dict or list recursively. :param key: The key to search for. :type key: str :param var: The dict or list to search in. :type var: dict or list :param wildcard: If True, the key can contain wildcards. :type wildcard: bool :param return_keys: If True, return the keys of the found items instead of the items themselves. :type return_keys: bool :param case_sensitive: If True, the search will be case sensitive. :type case_sensitive: bool :return: The found items. :rtype: Generator",
"func":1
},
{
"ref":"utils.validation.is_apk",
"url":8,
"doc":"Check if a module is APK related. :param module: The module to check. :type module: Module :return: True if the module is APK related. :rtype: bool",
"func":1
},
{
"ref":"utils.validation.Validator",
"url":8,
"doc":"Validate type given."
},
{
"ref":"utils.validation.Validator.bool",
"url":8,
"doc":"Type check obj and return True if ok, else raise error (or return false) :param obj: The object to type check :param raise_error: Raise the error if any. :type raise_error: bool :return: True if type check, Raise TypeError or False if mismatch :rtype: bool :raise TypeError: If type mismatch",
"func":1
},
{
"ref":"utils.validation.Validator.string",
"url":8,
"doc":"Type check obj and return True if ok, else raise error (or return false) :param obj: The object to type check :param raise_error: Raise the error if any. :type raise_error: bool :return: True if type check, Raise TypeError or False if mismatch :rtype: bool :raise TypeError: If type mismatch",
"func":1
},
{
"ref":"utils.validation.Validator.list",
"url":8,
"doc":"Type check obj and return True if ok, else raise error (or return false) :param obj: The object to type check :param raise_error: Raise the error if any. :type raise_error: bool :return: True if type check, Raise TypeError or False if mismatch :rtype: bool :raise TypeError: If type mismatch",
"func":1
},
{
"ref":"utils.validation.Validator.dict",
"url":8,
"doc":"Type check obj and return True if ok, else raise error (or return false) :param obj: The object to type check :param raise_error: Raise the error if any. :type raise_error: bool :return: True if type check, Raise TypeError or False if mismatch :rtype: bool :raise TypeError: If type mismatch",
"func":1
},
{
"ref":"utils.validation.Validator.int_or_float",
"url":8,
"doc":"Type check obj and return True if ok, else raise error (or return false) :param obj: The object to type check :param raise_error: Raise the error if any. :type raise_error: bool :return: True if type check, Raise TypeError or False if mismatch :rtype: bool :raise TypeError: If type mismatch",
"func":1
},
{
"ref":"utils.validation.Validator.int",
"url":8,
"doc":"Type check obj and return True if ok, else raise error (or return false) :param obj: The object to type check :param raise_error: Raise the error if any. :type raise_error: bool :return: True if type check, Raise TypeError or False if mismatch :rtype: bool :raise TypeError: If type mismatch",
"func":1
},
{
"ref":"utils.validation.Validator.float",
"url":8,
"doc":"Type check obj and return True if ok, else raise error (or return false) :param obj: The object to type check :param raise_error: Raise the error if any. :type raise_error: bool :return: True if type check, Raise TypeError or False if mismatch :rtype: bool :raise TypeError: If type mismatch",
"func":1
},
{
"ref":"utils.validation.Validator.obj",
"url":8,
"doc":"Type check obj and return True if ok, else raise error (or return false) :param obj: The object to type check :param raise_error: Raise the error if any. :param type_obj: Type to check :type raise_error: bool :return: True if type check, Raise TypeError or False if mismatch :rtype: bool :raise TypeError: If type mismatch",
"func":1
},
{
"ref":"utils.prune",
"url":9,
"doc":""
},
{
"ref":"utils.prune.pruner",
"url":9,
"doc":"Prune the data to remove the data that is not needed. :param data: The data to be pruned. :type data: dict :return: The pruned data. :rtype: dict",
"func":1
},
{
"ref":"utils.counter",
"url":10,
"doc":""
},
{
"ref":"utils.counter.count_occurrencies",
"url":10,
"doc":"Count word occurrences in a string. :param word: The word to find. :type word: str :param input_string: The input string where to search :type input_string: str :return: Counted occurrences. :rtype: str",
"func":1
},
{
"ref":"utils.configuration",
"url":11,
"doc":""
},
{
"ref":"utils.configuration.merge",
"url":11,
"doc":"Merge base with head dict. :param base: dict to get merged with head. :type base: dict :param head: dict to merge in base. :type head: dict :return: The merged dict. :rtype: dict",
"func":1
},
{
"ref":"utils.configuration.pretty",
"url":11,
"doc":"Pretty print dict. :param d: Dict or list to print in pretty mode :param indent: Intentation level. :type indent: int :param is_list: is it a list? recursive parameter :type is_list: bool",
"func":1
},
{
"ref":"utils.mitigations",
"url":12,
"doc":""
},
{
"ref":"utils.mitigations.load_mitigation",
"url":12,
"doc":"Wrapper for mitigation loader. :param mitigation_name: The object to type check :param raise_error: Raise the error if any. :type raise_error: bool :param force: Force the analysis and ingore the cache :type force: bool :return: Dict of the mitigation if present, empty dict or raise error if not :rtype: dict :raise FileNotFoundError: If mitigation not found",
"func":1
},
{
"ref":"utils.mitigations.MitigationLoader",
"url":12,
"doc":""
},
{
"ref":"utils.mitigations.MitigationLoader.load_mitigation",
"url":12,
"doc":"Load the mitigation and return the dict of the mitigation loaded :param mitigation_name: The object to type check :param raise_error: Raise the error if any. :type raise_error: bool :param force: Force the analysis and ingore the cache :type force: bool :return: Dict of the mitigation if present, empty dict or raise error if not :rtype: dict :raise FileNotFoundError: If mitigation not found",
"func":1
},
{
"ref":"utils.booleanize",
"url":13,
"doc":""
},
{
"ref":"utils.booleanize.boolean_results",
"url":13,
"doc":"Booleanize the results of one or more modules. :param modules: list of modules to be booleanized :type modules: list :param raw_results: dictionary of raw results :type raw_results: dict :return: dictionary of booleanized results :rtype: dict",
"func":1
},
{
"ref":"utils.urls",
"url":14,
"doc":""
},
{
"ref":"utils.urls.port_parse",
"url":14,
"doc":"Parse port, checks for validity. :param port: The port number. :type port: str :return: stripped port. :rtype: str :raise AssertionError: If invalid number of port.",
"func":1
},
{
"ref":"utils.urls.link_sep",
"url":14,
"doc":"Strip URL with and obtain url and port. :param input_url: The url to strip :type input_url: str :return: stripped url and the port. :rtype: list of str",
"func":1
},
{
"ref":"utils.urls.url_strip",
"url":14,
"doc":"Strip URL with regex and obtain domain (DEPRECATED, USE url_domain). deprecated 2.0.alpha Use :func: url_domain instead. :param input_url: The url to strip :type input_url: str :param strip_www: Strip also the www :type strip_www: bool :return: stripped url. :rtype: str",
"func":1
},
{
"ref":"utils.urls.url_domain",
"url":14,
"doc":"Strip URL and obtain domain. :param url: The url to strip :type url: str :param keep_subdomain: keep the subdomain, default True :type keep_subdomain: bool :return: stripped url. :rtype: str",
"func":1
},
{
"ref":"utils.urls.has_wildcard",
"url":14,
"doc":"Check if the url contains a wildcard in last subdomain. :param url: The url to check :type url: str :return: True if the url contains a wildcard in the last subdomain, False otherwise :rtype: bool",
"func":1
},
{
"ref":"utils.urls.remove_wildcard",
"url":14,
"doc":"Remove the wildcard from the last subdomain. :param url: The url to remove the wildcard from :type url: str :return: The url without the wildcard :rtype: str",
"func":1
},
{
"ref":"utils.urls.validate_ip",
"url":14,
"doc":"Validate an IP :param ip: String to check if it's an IP. :type ip: str :return: True if ip param it's an IP, false otherwise. :rtype: bool",
"func":1
},
{
"ref":"utils.globals",
"url":15,
"doc":""
},
{
"ref":"utils.output",
"url":16,
"doc":""
},
{
"ref":"utils.output.Class_table",
"url":16,
"doc":"Class to create table in markdown"
},
{
"ref":"utils.output.Class_table.wrap",
"url":16,
"doc":"Wrap text in table :param wrap: String to wrap :type wrap: str :return: Wrapped string :rtype: str",
"func":1
},
{
"ref":"utils.output.Class_table.heading",
"url":16,
"doc":"Create a table header :return: Table header :rtype: str",
"func":1
},
{
"ref":"utils.output.Class_table.bold",
"url":16,
"doc":"Create bold text in table :param string: String to bold :type string: str :return: Bolded string :rtype: str",
"func":1
},
{
"ref":"utils.output.Class_table.italic",
"url":16,
"doc":"Create italic text in table :param string: String to italic :type string: str :return: Italicized string :rtype: str",
"func":1
},
{
"ref":"utils.output.Class_table.title",
"url":16,
"doc":"Create title text in table :param string: String to title :type string: str :return: Titled string :rtype: str",
"func":1
},
{
"ref":"utils.output.recursive_parsing",
"url":16,
"doc":"Parse the output and prepare md for the report recursively. :param value: The object to prepare as output :param hlevel: The height level :type hlevel: int :param bold_instead: Instead of using H1, H2, H3,  . use a simple bold in markdown. :type bold_instead: bool :return: String to insert into the md file. :rtype: str",
"func":1
},
{
"ref":"utils.output.html_to_pdf",
"url":16,
"doc":"Convert an HTML file to PDF. :param source_path: The input HTML file path :type source_path: str :param output_filename: The output PDF file path :type source_path: str :param delete_html: Delete HTML file after doing the conversion. Default: True :type delete_html: bool",
"func":1
},
{
"ref":"utils.output.md_to_html",
"url":16,
"doc":"Convert an md string to HTML file. :param results: The results from the computation. :type results:dict :param extras: Extras of Markdown2 (check wiki) :type extras: list of str :param output_file: output file path :type output_file: str :param css_file: CSS file path to beautify the HTML output. :type css_file: str",
"func":1
},
{
"ref":"utils.output.title",
"url":16,
"doc":"Add title md style. :param string: The string to process. :type string:str :param level: depth level for the header (h1,h2,h3 ) :type level: int :return: Formatted String. :rtype: str",
"func":1
},
{
"ref":"utils.output.bold",
"url":16,
"doc":"Add bold md style. :param string: The string to process. :type string:str :return: Formatted String. :rtype: str",
"func":1
},
{
"ref":"utils.output.line",
"url":16,
"doc":"Add line md style. :return: Formatted line in md style. :rtype: str",
"func":1
},
{
"ref":"utils.output.italic",
"url":16,
"doc":"Add italic md style. :param string: The string to process. :type string:str :return: Formatted String. :rtype: str",
"func":1
},
{
"ref":"utils.output.code",
"url":16,
"doc":"Add code md style. :param string: The string to process. :type string:str :return: Formatted String. :rtype: str",
"func":1
},
{
"ref":"utils.output.multiline_code",
"url":16,
"doc":"Add multiline code md style. :param language: Language of the code (default NONE) :param string: The string to process. :type string:str :return: Formatted String. :rtype: str",
"func":1
},
{
"ref":"utils.colors",
"url":17,
"doc":"Color class for easy color manipulation"
},
{
"ref":"utils.colors.Color",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.HEADER",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.OKBLUE",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.OKCYAN",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.OKGREEN",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.WARNING",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.FAIL",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.ENDC",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.BOLD",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.UNDERLINE",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CEND",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CBOLD",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CITALIC",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CURL",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CBLINK",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CBLINK2",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CSELECTED",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CBLACK",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CRED",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CGREEN",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CYELLOW",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CBLUE",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CVIOLET",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CBEIGE",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CWHITE",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CBLACKBG",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CREDBG",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CGREENBG",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CYELLOWBG",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CBLUEBG",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CVIOLETBG",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CBEIGEBG",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CWHITEBG",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CGREY",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CRED2",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CGREEN2",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CYELLOW2",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CBLUE2",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CVIOLET2",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CBEIGE2",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CWHITE2",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CGREYBG",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CREDBG2",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CGREENBG2",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CYELLOWBG2",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CBLUEBG2",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CVIOLETBG2",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CBEIGEBG2",
"url":17,
"doc":""
},
{
"ref":"utils.colors.Color.CWHITEBG2",
"url":17,
"doc":""
},
{
"ref":"utils.subdomain_enumeration",
"url":18,
"doc":""
},
{
"ref":"utils.subdomain_enumeration.enumerate",
"url":18,
"doc":"Enumerate subdomains of a given hostname. :param hostname: The hostname to enumerate subdomains for. :return: A list of subdomains.",
"func":1
},
{
"ref":"modules",
"url":19,
"doc":""
},
{
"ref":"modules.stix",
"url":20,
"doc":""
},
{
"ref":"modules.stix.stix",
"url":21,
"doc":""
},
{
"ref":"modules.stix.stix.Stix",
"url":21,
"doc":"This class is used to create a STIX bundle for each module."
},
{
"ref":"modules.stix.stix.Stix.Type",
"url":21,
"doc":"Class used to indicate the type of STIX Analysis: Hosts or Modules."
},
{
"ref":"modules.stix.stix.Stix.run",
"url":21,
"doc":"",
"func":1
},
{
"ref":"modules.stix.stix.Stix.build",
"url":21,
"doc":"",
"func":1
},
{
"ref":"modules.stix.stix.Stix.build_and_save",
"url":21,
"doc":"",
"func":1
},
{
"ref":"modules.stix.stix.Stix.save_to_file",
"url":21,
"doc":"",
"func":1
},
{
"ref":"modules.stix.stix_base",
"url":22,
"doc":""
},
{
"ref":"modules.stix.stix_base.Bundled",
"url":22,
"doc":"This class will generate the bundle for the STIX2 objects dinamically from the mitigation. This class will generate the bundle for the STIX2 objects dinamically from the mitigation. The init method will initialize the object with the required parameters. :param mitigation_object: The mitigation object :type mitigation_object: dict :param vuln_args: The vulnerability arguments :type vuln_args: dict :param obs_args: The observed data arguments :type obs_args: dict :param coa_args: The course of action arguments :type coa_args: dict"
},
{
"ref":"modules.stix.stix_base.Bundled.sight_data",
"url":22,
"doc":"",
"func":1
},
{
"ref":"modules.android",
"url":23,
"doc":""
},
{
"ref":"modules.android.wrappers",
"url":24,
"doc":""
},
{
"ref":"modules.android.wrappers.mallodroid",
"url":25,
"doc":""
},
{
"ref":"modules.android.wrappers.mallodroid.Mallodroid",
"url":25,
"doc":"Mallodroid is a tool to perform static analysis of Android applications. This wrapper is a python wrapper to mallodroid.py."
},
{
"ref":"modules.android.wrappers.mallodroid.Mallodroid.input",
"url":25,
"doc":"This method is used to set the input :param kwargs: :Keyword Arguments: path: path to the file to be analyzed args: list of arguments to be passed to mallodroid force: force the analysis of the file (default: False)",
"func":1
},
{
"ref":"modules.android.wrappers.mallodroid.Mallodroid.output",
"url":25,
"doc":"This method is used to get the output of the analysis :param kwargs: :Keyword Arguments: path: path to the file to be analyzed :return: a dictionary result :rtype: dict",
"func":1
},
{
"ref":"modules.android.wrappers.mallodroid.Mallodroid.run",
"url":25,
"doc":"This method is used to run the analysis :param kwargs: :Keyword Arguments: path: path to the file to be analyzed args: list of arguments to be passed to mallodroid force: force the analysis of the file ignoring cache (default: False)",
"func":1
},
{
"ref":"modules.android.wrappers.super",
"url":26,
"doc":""
},
{
"ref":"modules.android.wrappers.super.Parser",
"url":26,
"doc":"Parser for SUPERAndroidAnalyzer results. :param results: JSON results from SUPERAndroidAnalyzer. :type results: dict"
},
{
"ref":"modules.android.wrappers.super.Parser.output",
"url":26,
"doc":"Returns the parsed results. :return: Parsed results. :rtype: dict",
"func":1
},
{
"ref":"modules.android.wrappers.super.Super",
"url":26,
"doc":"SuperAndroidAnalyzer is a tool to scan Android applications for vulnerabilities. This tool is a wrapper for the SUPER tool."
},
{
"ref":"modules.android.wrappers.super.Super.input",
"url":26,
"doc":"Parses the input arguments. :param kwargs: Dictionary of input arguments. :Keyword Arguments:   path ( str )  Path to the file to be scanned.   args ( list )  Additional arguments to be passed to SUPER.   force ( bool )  Force the scan even if the file is already scanned. :type kwargs: dict",
"func":1
},
{
"ref":"modules.android.wrappers.super.Super.output",
"url":26,
"doc":"Returns the parsed results. :param kwargs: Dictionary of input arguments. :Keyword Arguments:   path ( str )  Path to the file to be scanned. :type kwargs: dict :return: Parsed results. :rtype: dict",
"func":1
},
{
"ref":"modules.android.wrappers.super.Super.run",
"url":26,
"doc":"Runs SUPER. :param kwargs: Dictionary of input arguments. :Keyword Arguments:   path ( str )  Path to the file to be scanned.   args ( list )  Additional arguments to be passed to SUPER.   force ( bool )  Force the scan even if the file is already scanned. :type kwargs: dict",
"func":1
},
{
"ref":"modules.android.wrappers.super.Super.subprocess_call",
"url":26,
"doc":"Calls a subprocess and returns the output. :param cmd: Command to be executed. :type cmd: list :param null: File to be used as a null device. :type null: str :param try_again: If True, will try again if the subprocess call fails. :type try_again: bool :return: Output of the subprocess call, if fails return 2. :rtype: str or int",
"func":1
},
{
"ref":"modules.android.sslerror",
"url":27,
"doc":""
},
{
"ref":"modules.android.sslerror.Ssl_error",
"url":27,
"doc":"Checks if the application got any ssl error."
},
{
"ref":"modules.android.sslerror.Ssl_error.stix",
"url":27,
"doc":""
},
{
"ref":"modules.android.sslerror.Ssl_error.input",
"url":28,
"doc":"Inputs the arguments for the Mallodroid instance. :param kwargs: :Keyword Arguments: - path (str): Path to the apk file. - args (list): List of arguments to be passed to the Mallodroid instance. - force (bool): Force the execution of the Mallodroid instance.",
"func":1
},
{
"ref":"modules.android.sslerror.Ssl_error.run",
"url":28,
"doc":"Runs the Mallodroid module. :param kwargs: :Keyword Arguments: - path (str): Path to the apk file. - args (list): List of arguments to be passed to the Mallodroid instance. - force (bool): Force the execution of the Mallodroid instance.",
"func":1
},
{
"ref":"modules.android.sslerror.Ssl_error.output",
"url":28,
"doc":"Returns the output of the Mallodroid module. :return: The output of the Mallodroid module. :rtype: dict",
"func":1
},
{
"ref":"modules.android.obfuscated_code",
"url":29,
"doc":""
},
{
"ref":"modules.android.obfuscated_code.Obfuscated_code",
"url":29,
"doc":"Check if the code is obfuscated"
},
{
"ref":"modules.android.obfuscated_code.Obfuscated_code.stix",
"url":29,
"doc":""
},
{
"ref":"modules.android.obfuscated_code.Obfuscated_code.input",
"url":30,
"doc":"Receives the input arguments from the user. :param kwargs: input arguments :Keyword Arguments:   path ( str )  path to the file   args ( list )  list of arguments   force ( bool )  force the analysis",
"func":1
},
{
"ref":"modules.android.obfuscated_code.Obfuscated_code.run",
"url":30,
"doc":"Runs the analysis. :param kwargs: input arguments :Keyword Arguments:   path ( str )  path to the file   args ( list )  list of arguments   force ( bool )  force the analysis :return: results :rtype: dict :raise AssertionError: if the input arguments are not valid",
"func":1
},
{
"ref":"modules.android.mallodroid_base",
"url":28,
"doc":""
},
{
"ref":"modules.android.mallodroid_base.Mallodroid_base",
"url":28,
"doc":"Interface class for Mallodroid vulnerability detection."
},
{
"ref":"modules.android.mallodroid_base.Mallodroid_base.input",
"url":28,
"doc":"Inputs the arguments for the Mallodroid instance. :param kwargs: :Keyword Arguments: - path (str): Path to the apk file. - args (list): List of arguments to be passed to the Mallodroid instance. - force (bool): Force the execution of the Mallodroid instance.",
"func":1
},
{
"ref":"modules.android.mallodroid_base.Mallodroid_base.run",
"url":28,
"doc":"Runs the Mallodroid module. :param kwargs: :Keyword Arguments: - path (str): Path to the apk file. - args (list): List of arguments to be passed to the Mallodroid instance. - force (bool): Force the execution of the Mallodroid instance.",
"func":1
},
{
"ref":"modules.android.mallodroid_base.Mallodroid_base.output",
"url":28,
"doc":"Returns the output of the Mallodroid module. :return: The output of the Mallodroid module. :rtype: dict",
"func":1
},
{
"ref":"modules.android.trustmanager",
"url":31,
"doc":""
},
{
"ref":"modules.android.trustmanager.Trustmanager",
"url":31,
"doc":"Check if the app uses a custom TrustManager."
},
{
"ref":"modules.android.trustmanager.Trustmanager.stix",
"url":31,
"doc":""
},
{
"ref":"modules.android.trustmanager.Trustmanager.input",
"url":28,
"doc":"Inputs the arguments for the Mallodroid instance. :param kwargs: :Keyword Arguments: - path (str): Path to the apk file. - args (list): List of arguments to be passed to the Mallodroid instance. - force (bool): Force the execution of the Mallodroid instance.",
"func":1
},
{
"ref":"modules.android.trustmanager.Trustmanager.run",
"url":28,
"doc":"Runs the Mallodroid module. :param kwargs: :Keyword Arguments: - path (str): Path to the apk file. - args (list): List of arguments to be passed to the Mallodroid instance. - force (bool): Force the execution of the Mallodroid instance.",
"func":1
},
{
"ref":"modules.android.trustmanager.Trustmanager.output",
"url":28,
"doc":"Returns the output of the Mallodroid module. :return: The output of the Mallodroid module. :rtype: dict",
"func":1
},
{
"ref":"modules.android.weak_algorithms",
"url":32,
"doc":""
},
{
"ref":"modules.android.weak_algorithms.Weak_algorithms",
"url":32,
"doc":"Analyze the application to find the known weak algorithms."
},
{
"ref":"modules.android.weak_algorithms.Weak_algorithms.stix",
"url":32,
"doc":""
},
{
"ref":"modules.android.weak_algorithms.Weak_algorithms.input",
"url":30,
"doc":"Receives the input arguments from the user. :param kwargs: input arguments :Keyword Arguments:   path ( str )  path to the file   args ( list )  list of arguments   force ( bool )  force the analysis",
"func":1
},
{
"ref":"modules.android.weak_algorithms.Weak_algorithms.run",
"url":30,
"doc":"Runs the analysis. :param kwargs: input arguments :Keyword Arguments:   path ( str )  path to the file   args ( list )  list of arguments   force ( bool )  force the analysis :return: results :rtype: dict :raise AssertionError: if the input arguments are not valid",
"func":1
},
{
"ref":"modules.android.hostnameverifier",
"url":33,
"doc":""
},
{
"ref":"modules.android.hostnameverifier.Hostnameverifier",
"url":33,
"doc":"Checks if the device has a custom hostname."
},
{
"ref":"modules.android.hostnameverifier.Hostnameverifier.stix",
"url":33,
"doc":""
},
{
"ref":"modules.android.hostnameverifier.Hostnameverifier.input",
"url":28,
"doc":"Inputs the arguments for the Mallodroid instance. :param kwargs: :Keyword Arguments: - path (str): Path to the apk file. - args (list): List of arguments to be passed to the Mallodroid instance. - force (bool): Force the execution of the Mallodroid instance.",
"func":1
},
{
"ref":"modules.android.hostnameverifier.Hostnameverifier.run",
"url":28,
"doc":"Runs the Mallodroid module. :param kwargs: :Keyword Arguments: - path (str): Path to the apk file. - args (list): List of arguments to be passed to the Mallodroid instance. - force (bool): Force the execution of the Mallodroid instance.",
"func":1
},
{
"ref":"modules.android.hostnameverifier.Hostnameverifier.output",
"url":28,
"doc":"Returns the output of the Mallodroid module. :return: The output of the Mallodroid module. :rtype: dict",
"func":1
},
{
"ref":"modules.android.ssl_getinsecure_method",
"url":34,
"doc":""
},
{
"ref":"modules.android.ssl_getinsecure_method.Ssl_getinsecure_method",
"url":34,
"doc":"Check the presence of SSL getInsecure method in the application"
},
{
"ref":"modules.android.ssl_getinsecure_method.Ssl_getinsecure_method.stix",
"url":34,
"doc":""
},
{
"ref":"modules.android.ssl_getinsecure_method.Ssl_getinsecure_method.input",
"url":30,
"doc":"Receives the input arguments from the user. :param kwargs: input arguments :Keyword Arguments:   path ( str )  path to the file   args ( list )  list of arguments   force ( bool )  force the analysis",
"func":1
},
{
"ref":"modules.android.ssl_getinsecure_method.Ssl_getinsecure_method.run",
"url":30,
"doc":"Runs the analysis. :param kwargs: input arguments :Keyword Arguments:   path ( str )  path to the file   args ( list )  list of arguments   force ( bool )  force the analysis :return: results :rtype: dict :raise AssertionError: if the input arguments are not valid",
"func":1
},
{
"ref":"modules.android.webview_ssl_errors",
"url":35,
"doc":""
},
{
"ref":"modules.android.webview_ssl_errors.Webview_ssl_errors",
"url":35,
"doc":"Check if the WebView ignores SSL Errors."
},
{
"ref":"modules.android.webview_ssl_errors.Webview_ssl_errors.stix",
"url":35,
"doc":""
},
{
"ref":"modules.android.webview_ssl_errors.Webview_ssl_errors.input",
"url":30,
"doc":"Receives the input arguments from the user. :param kwargs: input arguments :Keyword Arguments:   path ( str )  path to the file   args ( list )  list of arguments   force ( bool )  force the analysis",
"func":1
},
{
"ref":"modules.android.webview_ssl_errors.Webview_ssl_errors.run",
"url":30,
"doc":"Runs the analysis. :param kwargs: input arguments :Keyword Arguments:   path ( str )  path to the file   args ( list )  list of arguments   force ( bool )  force the analysis :return: results :rtype: dict :raise AssertionError: if the input arguments are not valid",
"func":1
},
{
"ref":"modules.android.super_base",
"url":30,
"doc":""
},
{
"ref":"modules.android.super_base.Super_base",
"url":30,
"doc":"Interface for SUPERAndroidAnalyzer vulnerability detection."
},
{
"ref":"modules.android.super_base.Super_base.input",
"url":30,
"doc":"Receives the input arguments from the user. :param kwargs: input arguments :Keyword Arguments:   path ( str )  path to the file   args ( list )  list of arguments   force ( bool )  force the analysis",
"func":1
},
{
"ref":"modules.android.super_base.Super_base.run",
"url":30,
"doc":"Runs the analysis. :param kwargs: input arguments :Keyword Arguments:   path ( str )  path to the file   args ( list )  list of arguments   force ( bool )  force the analysis :return: results :rtype: dict :raise AssertionError: if the input arguments are not valid",
"func":1
},
{
"ref":"modules.android.super_base.Super_base.output",
"url":30,
"doc":"",
"func":1
},
{
"ref":"modules.parse_input_conf",
"url":36,
"doc":""
},
{
"ref":"modules.parse_input_conf.Parser",
"url":36,
"doc":"Parse input conf file and return a dict with the following structure: { \"name\": \"name of the project\", \"modules\": [ \"module1\", \"module2\",  . ], \"args\": { \"module1\": { \"arg1\": \"value\", \"arg2\": \"value\",  . }, \"module2\": { \"arg1\": \"value\", \"arg2\": \"value\",  . },  . } } :param to_parse: path to the configuration file or list of paths :type to_parse: str or list"
},
{
"ref":"modules.parse_input_conf.Parser.remove",
"url":36,
"doc":"Removes a configuration from the input dict :param data: input dict :param key: key to remove :param value: value to recusively remove",
"func":1
},
{
"ref":"modules.parse_input_conf.Parser.validate_include",
"url":36,
"doc":"Validates the included configuration file :param included: list of included file :type included: list :return: dict with the validated configuration :rtype: dict",
"func":1
},
{
"ref":"modules.parse_input_conf.Parser.output",
"url":36,
"doc":"Return the parsed configuration :return: parsed configuration :rtype: dict",
"func":1
},
{
"ref":"modules.server",
"url":37,
"doc":""
},
{
"ref":"modules.server.hsts_base",
"url":38,
"doc":""
},
{
"ref":"modules.server.hsts_base.Hsts_base",
"url":38,
"doc":"Hsts_base is the base class for all HSTS analysis. It is used to obtain the results of the analysis."
},
{
"ref":"modules.server.hsts_base.Hsts_base.input",
"url":38,
"doc":"Inputs the required data to the analysis. :param kwargs: data to be used for the analysis :type kwargs: dict :Keyword Arguments:   hostname ( str )  the hostname to be used for the analysis   force ( bool )  force the analysis to be run, default is True   port ( str )  the port to be used for the analysis   type ( str )  the type of analysis to be done",
"func":1
},
{
"ref":"modules.server.hsts_base.Hsts_base.run",
"url":38,
"doc":"Runs the analysis. :param kwargs: data to be used for the analysis :type kwargs: dict :Keyword Arguments:   hostname ( str )  the hostname to be used for the analysis   force ( bool )  force the analysis to be run, default is True   port ( str )  the port to be used for the analysis   type ( str )  the type of analysis to be done :return: the results from the analysis :rtype: dict",
"func":1
},
{
"ref":"modules.server.hsts_base.Hsts_base.output",
"url":38,
"doc":"Returns the results from the analysis. :return: the results from the analysis :rtype: dict",
"func":1
},
{
"ref":"modules.server.wrappers",
"url":39,
"doc":""
},
{
"ref":"modules.server.wrappers.https_hsts",
"url":40,
"doc":""
},
{
"ref":"modules.server.wrappers.https_hsts.Parse",
"url":40,
"doc":"Parse the results of the HSTS file :param moz: True if the mozilla file is to be parsed, False if the google file is to be parsed :type moz: bool"
},
{
"ref":"modules.server.wrappers.https_hsts.Parse.output",
"url":40,
"doc":"Return the results of the parsing :return: dict results :rtype: dict",
"func":1
},
{
"ref":"modules.server.wrappers.https_hsts.Https",
"url":40,
"doc":"Analyze the results of the request and return the results by choosing the right method asked"
},
{
"ref":"modules.server.wrappers.https_hsts.Https.HTTPS",
"url":40,
"doc":""
},
{
"ref":"modules.server.wrappers.https_hsts.Https.HSTSSET",
"url":40,
"doc":""
},
{
"ref":"modules.server.wrappers.https_hsts.Https.HSTSPRELOAD",
"url":40,
"doc":""
},
{
"ref":"modules.server.wrappers.https_hsts.Https.SERVERINFO",
"url":40,
"doc":""
},
{
"ref":"modules.server.wrappers.https_hsts.Https.input",
"url":40,
"doc":"Set the input parameters :param kwargs: input parameters :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to analyze   type ( int )  Type of HSTS to analyze   port ( int )  Port to analyze   force ( bool )  Force the analysis ignoring cache",
"func":1
},
{
"ref":"modules.server.wrappers.https_hsts.Https.output",
"url":40,
"doc":"Return the results of the analysis :param kwargs: output parameters :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to analyze :return: dict results :rtype: dict",
"func":1
},
{
"ref":"modules.server.wrappers.https_hsts.Https.run",
"url":40,
"doc":"Run the analysis :param kwargs: input parameters :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to analyze   type ( int )  Type of HSTS to analyze   port ( int )  Port to analyze   force ( bool )  Force the analysis ignoring cache :return: dict results :rtype: dict",
"func":1
},
{
"ref":"modules.server.wrappers.certificate",
"url":41,
"doc":""
},
{
"ref":"modules.server.wrappers.certificate.Parser",
"url":41,
"doc":"Parser for the crt.sh API :param results: The results from the crt.sh API :type results: list"
},
{
"ref":"modules.server.wrappers.certificate.Parser.output",
"url":41,
"doc":"Returns the cached results :return: The output of the crt.sh API",
"func":1
},
{
"ref":"modules.server.wrappers.certificate.Certificate",
"url":41,
"doc":"Calls the crt.sh API and returns the results"
},
{
"ref":"modules.server.wrappers.certificate.Certificate.input",
"url":41,
"doc":"Sets the input arguments :param kwargs: The input arguments :type kwargs: dict :Keyword Arguments:   hostname ( str )  The hostname to lookup   force ( bool )  Force the lookup",
"func":1
},
{
"ref":"modules.server.wrappers.certificate.Certificate.output",
"url":41,
"doc":"Returns the cached results :param kwargs: The input arguments :type kwargs: dict :Keyword Arguments:   hostname ( str )  The hostname to lookup :return: The cached results :rtype: dict",
"func":1
},
{
"ref":"modules.server.wrappers.certificate.Certificate.run",
"url":41,
"doc":"Runs the crt.sh API :param kwargs: The input arguments :type kwargs: dict :Keyword Arguments:   hostname ( str )  The hostname to lookup   force ( bool )  Force the lookup   expired ( bool )  Include or exclude expired certificates, default is False (excluded) :return: The cached results :rtype: dict",
"func":1
},
{
"ref":"modules.server.wrappers.tlsfuzzer",
"url":42,
"doc":""
},
{
"ref":"modules.server.wrappers.tlsfuzzer.Tlsfuzzer",
"url":42,
"doc":"Tlsfuzzer is a tool for testing TLS connections. this is a wrapper around tlslite and tlsfuzzer."
},
{
"ref":"modules.server.wrappers.tlsfuzzer.Tlsfuzzer.input",
"url":42,
"doc":"Input arguments for tlsfuzzer. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to analyze.   scripts ( list )  Scripts to run.   port ( str )  Port to connect to.   force ( bool )  Force to run the script by ignoring cache.",
"func":1
},
{
"ref":"modules.server.wrappers.tlsfuzzer.Tlsfuzzer.output",
"url":42,
"doc":"Output of tlsfuzzer. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to analyze.   scripts ( list )  Scripts to run.",
"func":1
},
{
"ref":"modules.server.wrappers.tlsfuzzer.Tlsfuzzer.run",
"url":42,
"doc":"Run tlsfuzzer. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to analyze.   scripts ( list )  Scripts to run.   port ( str )  Port to connect to.   force ( bool )  Force to run the script by ignoring cache. :return: dict  Output of tlsfuzzer. :rtype: dict",
"func":1
},
{
"ref":"modules.server.wrappers.testssl",
"url":43,
"doc":""
},
{
"ref":"modules.server.wrappers.testssl.Parser",
"url":43,
"doc":"Class used to parse tlsfuzzer results. The results are parsed and grouped by IP/SITE. Init method. :param to_parse: Raw JSON output of testssl.sh, given as a python dict. :type to_parse: dict"
},
{
"ref":"modules.server.wrappers.testssl.Parser.output",
"url":43,
"doc":"Output. :return: returns parsed cache dicts. :rtype: tuple of dict",
"func":1
},
{
"ref":"modules.server.wrappers.testssl.Testssl",
"url":43,
"doc":"Testssl wrapper module. Loads testssl variables."
},
{
"ref":"modules.server.wrappers.testssl.Testssl.input",
"url":43,
"doc":"Set the input for the modules :param kwargs: See below :Keyword Arguments:   hostname ( str )  The hostname of the website to analyze. Can be an IP or a Name (DNS)   args ( list of str )  Raw arguments for testssl.sh executable   force ( bool )  Force rescan by ignoring cached results , Default  False   one ( bool )  Add   IP=one to testssl.sh executable calls, default  True   clean ( bool )  clear the cache, default  False ",
"func":1
},
{
"ref":"modules.server.wrappers.testssl.Testssl.output",
"url":43,
"doc":"Output method of module :param kwargs: See below :Keyword Arguments:   hostname ( str )  The hostname of the website analyzed. Can be an IP or a Name (DNS). :return: Empty dict if not found, results dict if found. :rtype: dict :raise AssertionError: If hostname parameter is not found.",
"func":1
},
{
"ref":"modules.server.wrappers.testssl.Testssl.run",
"url":43,
"doc":"Set the input for the modules, processes the request and returns output. :param kwargs: See below :Keyword Arguments:   hostname ( str )  The hostname of the website to analyze. Can be an IP or a Name (DNS)   args ( list of str )  Raw arguments for testssl.sh executable   force ( bool )  Force rescan by ignoring cached results , Default  False   one ( bool )  Add   IP=one to testssl.sh executable calls, default  True   clean ( bool )  clear the cache, default  False :return: Parsed results. :rtype: dict :raise AssertionError: If hostname parameter is not found.",
"func":1
},
{
"ref":"modules.server.crime",
"url":44,
"doc":""
},
{
"ref":"modules.server.crime.Crime",
"url":44,
"doc":"Testssl.sh is a tool to test the SSL configuration of a server. This is a base class for the different vulnerabilities found by testssl.sh."
},
{
"ref":"modules.server.crime.Crime.conf",
"url":44,
"doc":""
},
{
"ref":"modules.server.crime.Crime.stix",
"url":44,
"doc":"Analysis of the crime testssl results"
},
{
"ref":"modules.server.crime.Crime.input",
"url":45,
"doc":"This method is used to set the input parameters for the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   force ( bool )  Force the analysis.   port ( str )  Port to be analyzed.   keys ( list )  List of keys to be analyzed.",
"func":1
},
{
"ref":"modules.server.crime.Crime.run",
"url":45,
"doc":"This method is used to run the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   port ( str )  Port to be analyzed.   force ( bool )  Force the analysis.   keys ( list )  List of keys to be analyzed. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.crime.Crime.output",
"url":45,
"doc":"This method is used to output the results of the analysis. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.logjam",
"url":46,
"doc":""
},
{
"ref":"modules.server.logjam.Logjam",
"url":46,
"doc":"Analysis of the logjam testssl results"
},
{
"ref":"modules.server.logjam.Logjam.stix",
"url":46,
"doc":""
},
{
"ref":"modules.server.logjam.Logjam.input",
"url":45,
"doc":"This method is used to set the input parameters for the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   force ( bool )  Force the analysis.   port ( str )  Port to be analyzed.   keys ( list )  List of keys to be analyzed.",
"func":1
},
{
"ref":"modules.server.logjam.Logjam.run",
"url":45,
"doc":"This method is used to run the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   port ( str )  Port to be analyzed.   force ( bool )  Force the analysis.   keys ( list )  List of keys to be analyzed. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.logjam.Logjam.output",
"url":45,
"doc":"This method is used to output the results of the analysis. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.heartbleed",
"url":47,
"doc":""
},
{
"ref":"modules.server.heartbleed.Heartbleed",
"url":47,
"doc":"Analysis of the heartbleed testssl results"
},
{
"ref":"modules.server.heartbleed.Heartbleed.stix",
"url":47,
"doc":""
},
{
"ref":"modules.server.heartbleed.Heartbleed.input",
"url":45,
"doc":"This method is used to set the input parameters for the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   force ( bool )  Force the analysis.   port ( str )  Port to be analyzed.   keys ( list )  List of keys to be analyzed.",
"func":1
},
{
"ref":"modules.server.heartbleed.Heartbleed.run",
"url":45,
"doc":"This method is used to run the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   port ( str )  Port to be analyzed.   force ( bool )  Force the analysis.   keys ( list )  List of keys to be analyzed. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.heartbleed.Heartbleed.output",
"url":45,
"doc":"This method is used to output the results of the analysis. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.drown",
"url":48,
"doc":""
},
{
"ref":"modules.server.drown.Drown",
"url":48,
"doc":"Testssl.sh is a tool to test the SSL configuration of a server. This is a base class for the different vulnerabilities found by testssl.sh."
},
{
"ref":"modules.server.drown.Drown.conf",
"url":48,
"doc":""
},
{
"ref":"modules.server.drown.Drown.stix",
"url":48,
"doc":"Analysis of the drown testssl results"
},
{
"ref":"modules.server.drown.Drown.input",
"url":45,
"doc":"This method is used to set the input parameters for the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   force ( bool )  Force the analysis.   port ( str )  Port to be analyzed.   keys ( list )  List of keys to be analyzed.",
"func":1
},
{
"ref":"modules.server.drown.Drown.run",
"url":45,
"doc":"This method is used to run the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   port ( str )  Port to be analyzed.   force ( bool )  Force the analysis.   keys ( list )  List of keys to be analyzed. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.drown.Drown.output",
"url":45,
"doc":"This method is used to output the results of the analysis. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.pfs",
"url":49,
"doc":""
},
{
"ref":"modules.server.pfs.Pfs",
"url":49,
"doc":"Analysis of the pfs testssl results"
},
{
"ref":"modules.server.pfs.Pfs.stix",
"url":49,
"doc":""
},
{
"ref":"modules.server.pfs.Pfs.input",
"url":45,
"doc":"This method is used to set the input parameters for the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   force ( bool )  Force the analysis.   port ( str )  Port to be analyzed.   keys ( list )  List of keys to be analyzed.",
"func":1
},
{
"ref":"modules.server.pfs.Pfs.run",
"url":45,
"doc":"This method is used to run the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   port ( str )  Port to be analyzed.   force ( bool )  Force the analysis.   keys ( list )  List of keys to be analyzed. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.pfs.Pfs.output",
"url":45,
"doc":"This method is used to output the results of the analysis. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.hsts_set",
"url":50,
"doc":""
},
{
"ref":"modules.server.hsts_set.Hsts_set",
"url":50,
"doc":"Analize results and check if HSTS is set"
},
{
"ref":"modules.server.hsts_set.Hsts_set.conf",
"url":50,
"doc":""
},
{
"ref":"modules.server.hsts_set.Hsts_set.stix",
"url":50,
"doc":""
},
{
"ref":"modules.server.hsts_set.Hsts_set.input",
"url":38,
"doc":"Inputs the required data to the analysis. :param kwargs: data to be used for the analysis :type kwargs: dict :Keyword Arguments:   hostname ( str )  the hostname to be used for the analysis   force ( bool )  force the analysis to be run, default is True   port ( str )  the port to be used for the analysis   type ( str )  the type of analysis to be done",
"func":1
},
{
"ref":"modules.server.hsts_set.Hsts_set.run",
"url":38,
"doc":"Runs the analysis. :param kwargs: data to be used for the analysis :type kwargs: dict :Keyword Arguments:   hostname ( str )  the hostname to be used for the analysis   force ( bool )  force the analysis to be run, default is True   port ( str )  the port to be used for the analysis   type ( str )  the type of analysis to be done :return: the results from the analysis :rtype: dict",
"func":1
},
{
"ref":"modules.server.hsts_set.Hsts_set.output",
"url":38,
"doc":"Returns the results from the analysis. :return: the results from the analysis :rtype: dict",
"func":1
},
{
"ref":"modules.server.testssl_base",
"url":45,
"doc":""
},
{
"ref":"modules.server.testssl_base.Testssl_base",
"url":45,
"doc":"Testssl.sh is a tool to test the SSL configuration of a server. This is a base class for the different vulnerabilities found by testssl.sh."
},
{
"ref":"modules.server.testssl_base.Testssl_base.input",
"url":45,
"doc":"This method is used to set the input parameters for the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   force ( bool )  Force the analysis.   port ( str )  Port to be analyzed.   keys ( list )  List of keys to be analyzed.",
"func":1
},
{
"ref":"modules.server.testssl_base.Testssl_base.run",
"url":45,
"doc":"This method is used to run the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   port ( str )  Port to be analyzed.   force ( bool )  Force the analysis.   keys ( list )  List of keys to be analyzed. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.testssl_base.Testssl_base.output",
"url":45,
"doc":"This method is used to output the results of the analysis. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.three_shake",
"url":51,
"doc":""
},
{
"ref":"modules.server.three_shake.Three_shake",
"url":51,
"doc":"Analysis of the 3shake testssl results"
},
{
"ref":"modules.server.three_shake.Three_shake.stix",
"url":51,
"doc":""
},
{
"ref":"modules.server.three_shake.Three_shake.input",
"url":45,
"doc":"This method is used to set the input parameters for the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   force ( bool )  Force the analysis.   port ( str )  Port to be analyzed.   keys ( list )  List of keys to be analyzed.",
"func":1
},
{
"ref":"modules.server.three_shake.Three_shake.run",
"url":45,
"doc":"This method is used to run the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   port ( str )  Port to be analyzed.   force ( bool )  Force the analysis.   keys ( list )  List of keys to be analyzed. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.three_shake.Three_shake.output",
"url":45,
"doc":"This method is used to output the results of the analysis. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.renegotiation",
"url":52,
"doc":""
},
{
"ref":"modules.server.renegotiation.Renegotiation",
"url":52,
"doc":"Analysis of the renego testssl results"
},
{
"ref":"modules.server.renegotiation.Renegotiation.stix",
"url":52,
"doc":""
},
{
"ref":"modules.server.renegotiation.Renegotiation.input",
"url":45,
"doc":"This method is used to set the input parameters for the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   force ( bool )  Force the analysis.   port ( str )  Port to be analyzed.   keys ( list )  List of keys to be analyzed.",
"func":1
},
{
"ref":"modules.server.renegotiation.Renegotiation.run",
"url":45,
"doc":"This method is used to run the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   port ( str )  Port to be analyzed.   force ( bool )  Force the analysis.   keys ( list )  List of keys to be analyzed. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.renegotiation.Renegotiation.output",
"url":45,
"doc":"This method is used to output the results of the analysis. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.breach",
"url":53,
"doc":""
},
{
"ref":"modules.server.breach.Breach",
"url":53,
"doc":"Analysis of the breach testssl results"
},
{
"ref":"modules.server.breach.Breach.stix",
"url":53,
"doc":""
},
{
"ref":"modules.server.breach.Breach.input",
"url":45,
"doc":"This method is used to set the input parameters for the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   force ( bool )  Force the analysis.   port ( str )  Port to be analyzed.   keys ( list )  List of keys to be analyzed.",
"func":1
},
{
"ref":"modules.server.breach.Breach.run",
"url":45,
"doc":"This method is used to run the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   port ( str )  Port to be analyzed.   force ( bool )  Force the analysis.   keys ( list )  List of keys to be analyzed. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.breach.Breach.output",
"url":45,
"doc":"This method is used to output the results of the analysis. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.sweet32",
"url":54,
"doc":""
},
{
"ref":"modules.server.sweet32.Sweet32",
"url":54,
"doc":"Analysis of the sweet32 testssl results"
},
{
"ref":"modules.server.sweet32.Sweet32.conf",
"url":54,
"doc":""
},
{
"ref":"modules.server.sweet32.Sweet32.stix",
"url":54,
"doc":""
},
{
"ref":"modules.server.sweet32.Sweet32.input",
"url":45,
"doc":"This method is used to set the input parameters for the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   force ( bool )  Force the analysis.   port ( str )  Port to be analyzed.   keys ( list )  List of keys to be analyzed.",
"func":1
},
{
"ref":"modules.server.sweet32.Sweet32.run",
"url":45,
"doc":"This method is used to run the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   port ( str )  Port to be analyzed.   force ( bool )  Force the analysis.   keys ( list )  List of keys to be analyzed. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.sweet32.Sweet32.output",
"url":45,
"doc":"This method is used to output the results of the analysis. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.sloth",
"url":55,
"doc":""
},
{
"ref":"modules.server.sloth.Sloth",
"url":55,
"doc":"Analysis of the sloth tlsfuzzer output"
},
{
"ref":"modules.server.sloth.Sloth.stix",
"url":55,
"doc":""
},
{
"ref":"modules.server.sloth.Sloth.input",
"url":56,
"doc":"Set input arguments for the analysis :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be tested   force ( bool )  Force the analysis   port ( str )  Port to be tested   scripts ( list )  List of scripts to be executed",
"func":1
},
{
"ref":"modules.server.sloth.Sloth.run",
"url":56,
"doc":"Run the analysis :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be tested   port ( str )  Port to be tested   force ( bool )  Force the analysis   scripts ( list )  List of scripts to be executed :return: results of the analysis :rtype: dict",
"func":1
},
{
"ref":"modules.server.sloth.Sloth.output",
"url":56,
"doc":"Obtain results of the analysis :return: results of the analysis :rtype: dict",
"func":1
},
{
"ref":"modules.server.ccs_injection",
"url":57,
"doc":""
},
{
"ref":"modules.server.ccs_injection.Ccs_injection",
"url":57,
"doc":"Analysis of the css_injection testssl results"
},
{
"ref":"modules.server.ccs_injection.Ccs_injection.stix",
"url":57,
"doc":""
},
{
"ref":"modules.server.ccs_injection.Ccs_injection.input",
"url":45,
"doc":"This method is used to set the input parameters for the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   force ( bool )  Force the analysis.   port ( str )  Port to be analyzed.   keys ( list )  List of keys to be analyzed.",
"func":1
},
{
"ref":"modules.server.ccs_injection.Ccs_injection.run",
"url":45,
"doc":"This method is used to run the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   port ( str )  Port to be analyzed.   force ( bool )  Force the analysis.   keys ( list )  List of keys to be analyzed. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.ccs_injection.Ccs_injection.output",
"url":45,
"doc":"This method is used to output the results of the analysis. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.nomore",
"url":58,
"doc":""
},
{
"ref":"modules.server.nomore.Nomore",
"url":58,
"doc":"Analysis of the nomore testssl results"
},
{
"ref":"modules.server.nomore.Nomore.conf",
"url":58,
"doc":""
},
{
"ref":"modules.server.nomore.Nomore.stix",
"url":58,
"doc":""
},
{
"ref":"modules.server.nomore.Nomore.input",
"url":45,
"doc":"This method is used to set the input parameters for the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   force ( bool )  Force the analysis.   port ( str )  Port to be analyzed.   keys ( list )  List of keys to be analyzed.",
"func":1
},
{
"ref":"modules.server.nomore.Nomore.run",
"url":45,
"doc":"This method is used to run the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   port ( str )  Port to be analyzed.   force ( bool )  Force the analysis.   keys ( list )  List of keys to be analyzed. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.nomore.Nomore.output",
"url":45,
"doc":"This method is used to output the results of the analysis. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.tlsfuzzer_base",
"url":56,
"doc":""
},
{
"ref":"modules.server.tlsfuzzer_base.Tlsfuzzer_base",
"url":56,
"doc":"Interface for TLSFuzzer Vulnerability Analysis"
},
{
"ref":"modules.server.tlsfuzzer_base.Tlsfuzzer_base.input",
"url":56,
"doc":"Set input arguments for the analysis :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be tested   force ( bool )  Force the analysis   port ( str )  Port to be tested   scripts ( list )  List of scripts to be executed",
"func":1
},
{
"ref":"modules.server.tlsfuzzer_base.Tlsfuzzer_base.run",
"url":56,
"doc":"Run the analysis :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be tested   port ( str )  Port to be tested   force ( bool )  Force the analysis   scripts ( list )  List of scripts to be executed :return: results of the analysis :rtype: dict",
"func":1
},
{
"ref":"modules.server.tlsfuzzer_base.Tlsfuzzer_base.output",
"url":56,
"doc":"Obtain results of the analysis :return: results of the analysis :rtype: dict",
"func":1
},
{
"ref":"modules.server.certificate_transparency",
"url":59,
"doc":""
},
{
"ref":"modules.server.certificate_transparency.Certificate_transparency",
"url":59,
"doc":"Analysis of the certificate transparency testssl results"
},
{
"ref":"modules.server.certificate_transparency.Certificate_transparency.stix",
"url":59,
"doc":""
},
{
"ref":"modules.server.certificate_transparency.Certificate_transparency.input",
"url":45,
"doc":"This method is used to set the input parameters for the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   force ( bool )  Force the analysis.   port ( str )  Port to be analyzed.   keys ( list )  List of keys to be analyzed.",
"func":1
},
{
"ref":"modules.server.certificate_transparency.Certificate_transparency.run",
"url":45,
"doc":"This method is used to run the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   port ( str )  Port to be analyzed.   force ( bool )  Force the analysis.   keys ( list )  List of keys to be analyzed. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.certificate_transparency.Certificate_transparency.output",
"url":45,
"doc":"This method is used to output the results of the analysis. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.https_enforced",
"url":60,
"doc":""
},
{
"ref":"modules.server.https_enforced.Https_enforced",
"url":60,
"doc":"This function checks if the server is configured to enforce HTTPS."
},
{
"ref":"modules.server.https_enforced.Https_enforced.conf",
"url":60,
"doc":""
},
{
"ref":"modules.server.https_enforced.Https_enforced.stix",
"url":60,
"doc":""
},
{
"ref":"modules.server.https_enforced.Https_enforced.input",
"url":38,
"doc":"Inputs the required data to the analysis. :param kwargs: data to be used for the analysis :type kwargs: dict :Keyword Arguments:   hostname ( str )  the hostname to be used for the analysis   force ( bool )  force the analysis to be run, default is True   port ( str )  the port to be used for the analysis   type ( str )  the type of analysis to be done",
"func":1
},
{
"ref":"modules.server.https_enforced.Https_enforced.run",
"url":38,
"doc":"Runs the analysis. :param kwargs: data to be used for the analysis :type kwargs: dict :Keyword Arguments:   hostname ( str )  the hostname to be used for the analysis   force ( bool )  force the analysis to be run, default is True   port ( str )  the port to be used for the analysis   type ( str )  the type of analysis to be done :return: the results from the analysis :rtype: dict",
"func":1
},
{
"ref":"modules.server.https_enforced.Https_enforced.output",
"url":38,
"doc":"Returns the results from the analysis. :return: the results from the analysis :rtype: dict",
"func":1
},
{
"ref":"modules.server.freak",
"url":61,
"doc":""
},
{
"ref":"modules.server.freak.Freak",
"url":61,
"doc":"Analysis of the freak testssl results"
},
{
"ref":"modules.server.freak.Freak.stix",
"url":61,
"doc":""
},
{
"ref":"modules.server.freak.Freak.input",
"url":45,
"doc":"This method is used to set the input parameters for the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   force ( bool )  Force the analysis.   port ( str )  Port to be analyzed.   keys ( list )  List of keys to be analyzed.",
"func":1
},
{
"ref":"modules.server.freak.Freak.run",
"url":45,
"doc":"This method is used to run the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   port ( str )  Port to be analyzed.   force ( bool )  Force the analysis.   keys ( list )  List of keys to be analyzed. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.freak.Freak.output",
"url":45,
"doc":"This method is used to output the results of the analysis. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.mitzvah",
"url":62,
"doc":""
},
{
"ref":"modules.server.mitzvah.Mitzvah",
"url":62,
"doc":"Analysis of the mitzvah testssl results"
},
{
"ref":"modules.server.mitzvah.Mitzvah.conf",
"url":62,
"doc":""
},
{
"ref":"modules.server.mitzvah.Mitzvah.stix",
"url":62,
"doc":""
},
{
"ref":"modules.server.mitzvah.Mitzvah.input",
"url":45,
"doc":"This method is used to set the input parameters for the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   force ( bool )  Force the analysis.   port ( str )  Port to be analyzed.   keys ( list )  List of keys to be analyzed.",
"func":1
},
{
"ref":"modules.server.mitzvah.Mitzvah.run",
"url":45,
"doc":"This method is used to run the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   port ( str )  Port to be analyzed.   force ( bool )  Force the analysis.   keys ( list )  List of keys to be analyzed. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.mitzvah.Mitzvah.output",
"url":45,
"doc":"This method is used to output the results of the analysis. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.hsts_preloading",
"url":63,
"doc":""
},
{
"ref":"modules.server.hsts_preloading.Hsts_preloading",
"url":63,
"doc":"Analysis of the HSTS Preloading status"
},
{
"ref":"modules.server.hsts_preloading.Hsts_preloading.stix",
"url":63,
"doc":""
},
{
"ref":"modules.server.hsts_preloading.Hsts_preloading.input",
"url":38,
"doc":"Inputs the required data to the analysis. :param kwargs: data to be used for the analysis :type kwargs: dict :Keyword Arguments:   hostname ( str )  the hostname to be used for the analysis   force ( bool )  force the analysis to be run, default is True   port ( str )  the port to be used for the analysis   type ( str )  the type of analysis to be done",
"func":1
},
{
"ref":"modules.server.hsts_preloading.Hsts_preloading.run",
"url":38,
"doc":"Runs the analysis. :param kwargs: data to be used for the analysis :type kwargs: dict :Keyword Arguments:   hostname ( str )  the hostname to be used for the analysis   force ( bool )  force the analysis to be run, default is True   port ( str )  the port to be used for the analysis   type ( str )  the type of analysis to be done :return: the results from the analysis :rtype: dict",
"func":1
},
{
"ref":"modules.server.hsts_preloading.Hsts_preloading.output",
"url":38,
"doc":"Returns the results from the analysis. :return: the results from the analysis :rtype: dict",
"func":1
},
{
"ref":"modules.server.ticketbleed",
"url":64,
"doc":""
},
{
"ref":"modules.server.ticketbleed.Ticketbleed",
"url":64,
"doc":"Analysis of the ticketbleed testssl results"
},
{
"ref":"modules.server.ticketbleed.Ticketbleed.stix",
"url":64,
"doc":""
},
{
"ref":"modules.server.ticketbleed.Ticketbleed.input",
"url":45,
"doc":"This method is used to set the input parameters for the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   force ( bool )  Force the analysis.   port ( str )  Port to be analyzed.   keys ( list )  List of keys to be analyzed.",
"func":1
},
{
"ref":"modules.server.ticketbleed.Ticketbleed.run",
"url":45,
"doc":"This method is used to run the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   port ( str )  Port to be analyzed.   force ( bool )  Force the analysis.   keys ( list )  List of keys to be analyzed. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.ticketbleed.Ticketbleed.output",
"url":45,
"doc":"This method is used to output the results of the analysis. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.robot",
"url":65,
"doc":""
},
{
"ref":"modules.server.robot.Robot",
"url":65,
"doc":"Testssl.sh is a tool to test the SSL configuration of a server. This is a base class for the different vulnerabilities found by testssl.sh."
},
{
"ref":"modules.server.robot.Robot.conf",
"url":65,
"doc":""
},
{
"ref":"modules.server.robot.Robot.stix",
"url":65,
"doc":"Analysis of the robot testssl results"
},
{
"ref":"modules.server.robot.Robot.input",
"url":45,
"doc":"This method is used to set the input parameters for the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   force ( bool )  Force the analysis.   port ( str )  Port to be analyzed.   keys ( list )  List of keys to be analyzed.",
"func":1
},
{
"ref":"modules.server.robot.Robot.run",
"url":45,
"doc":"This method is used to run the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   port ( str )  Port to be analyzed.   force ( bool )  Force the analysis.   keys ( list )  List of keys to be analyzed. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.robot.Robot.output",
"url":45,
"doc":"This method is used to output the results of the analysis. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.beast",
"url":66,
"doc":""
},
{
"ref":"modules.server.beast.Beast",
"url":66,
"doc":"Analysis of the beast testssl results"
},
{
"ref":"modules.server.beast.Beast.stix",
"url":66,
"doc":""
},
{
"ref":"modules.server.beast.Beast.input",
"url":45,
"doc":"This method is used to set the input parameters for the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   force ( bool )  Force the analysis.   port ( str )  Port to be analyzed.   keys ( list )  List of keys to be analyzed.",
"func":1
},
{
"ref":"modules.server.beast.Beast.run",
"url":45,
"doc":"This method is used to run the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   port ( str )  Port to be analyzed.   force ( bool )  Force the analysis.   keys ( list )  List of keys to be analyzed. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.beast.Beast.output",
"url":45,
"doc":"This method is used to output the results of the analysis. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.poodle",
"url":67,
"doc":""
},
{
"ref":"modules.server.poodle.Poodle",
"url":67,
"doc":"Analysis of the poodle testssl results"
},
{
"ref":"modules.server.poodle.Poodle.conf",
"url":67,
"doc":""
},
{
"ref":"modules.server.poodle.Poodle.stix",
"url":67,
"doc":""
},
{
"ref":"modules.server.poodle.Poodle.input",
"url":45,
"doc":"This method is used to set the input parameters for the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   force ( bool )  Force the analysis.   port ( str )  Port to be analyzed.   keys ( list )  List of keys to be analyzed.",
"func":1
},
{
"ref":"modules.server.poodle.Poodle.run",
"url":45,
"doc":"This method is used to run the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   port ( str )  Port to be analyzed.   force ( bool )  Force the analysis.   keys ( list )  List of keys to be analyzed. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.poodle.Poodle.output",
"url":45,
"doc":"This method is used to output the results of the analysis. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.lucky13",
"url":68,
"doc":""
},
{
"ref":"modules.server.lucky13.Lucky13",
"url":68,
"doc":"Analysis of the lucky13 testssl results"
},
{
"ref":"modules.server.lucky13.Lucky13.stix",
"url":68,
"doc":""
},
{
"ref":"modules.server.lucky13.Lucky13.input",
"url":45,
"doc":"This method is used to set the input parameters for the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   force ( bool )  Force the analysis.   port ( str )  Port to be analyzed.   keys ( list )  List of keys to be analyzed.",
"func":1
},
{
"ref":"modules.server.lucky13.Lucky13.run",
"url":45,
"doc":"This method is used to run the analysis. :param kwargs: :type kwargs: dict :Keyword Arguments:   hostname ( str )  Hostname to be analyzed.   port ( str )  Port to be analyzed.   force ( bool )  Force the analysis.   keys ( list )  List of keys to be analyzed. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.server.lucky13.Lucky13.output",
"url":45,
"doc":"This method is used to output the results of the analysis. :return: The results of the analysis. :rtype: dict",
"func":1
},
{
"ref":"modules.core",
"url":69,
"doc":""
},
{
"ref":"modules.core.Core",
"url":69,
"doc":"Core module :param hostname_or_path: hostname or path to scan :type hostname_or_path: str or list :param configuration: path to configuration file :type configuration: str or list :param output: path to output file :type output: str or list :param output_type: type of output :type output_type: str or list :param type_of_analysis: type of analysis :type type_of_analysis: str or list :param to_exclude: list of domains to exclude :type to_exclude: str or list :param group_by: choose what to group by in the output :type group_by: str :param apply_fix: apply a fix to the scan :type apply_fix: str :param openssl_version: version of openssl to use :type openssl_version: str :param ignore_openssl: ignore openssl version :type ignore_openssl: bool :param stix: generate stix report :type stix: bool"
},
{
"ref":"modules.core.Core.Report",
"url":69,
"doc":"Enum class for different report types"
},
{
"ref":"modules.core.Core.Analysis",
"url":69,
"doc":"Enum class for different analysis types"
},
{
"ref":"modules.core.Core.input",
"url":69,
"doc":"",
"func":1
},
{
"ref":"modules.configuration",
"url":70,
"doc":""
},
{
"ref":"modules.configuration.configuration_base",
"url":71,
"doc":""
},
{
"ref":"modules.configuration.configuration_base.OpenSSL",
"url":71,
"doc":"OpenSSL version comparison class."
},
{
"ref":"modules.configuration.configuration_base.OpenSSL.VERSION",
"url":71,
"doc":""
},
{
"ref":"modules.configuration.configuration_base.OpenSSL.less_than",
"url":71,
"doc":"Compare two OpenSSL versions, return True if ver1 < ver2. :param ver1: OpenSSL version string. :type ver1: str :param ver2: OpenSSL version string. :type ver2: str :default ver2: OpenSSL system version. :return: True if ver1 < ver2, else False. :rtype: bool",
"func":1
},
{
"ref":"modules.configuration.configuration_base.OpenSSL.greater_than",
"url":71,
"doc":"Compare two OpenSSL versions, return True if ver1 >= ver2. :param ver1: OpenSSL version string. :type ver1: str :param ver2: OpenSSL version string. :type ver2: str :default ver2: OpenSSL system version. :return: True if ver1 < ver2, else False. :rtype: bool",
"func":1
},
{
"ref":"modules.configuration.configuration_base.OpenSSL.is_safe",
"url":71,
"doc":"Compare two OpenSSL versions, alias for less_than. :param ver1: OpenSSL version string. :type ver1: str :param ver2: OpenSSL version string. :type ver2: str :default ver2: OpenSSL system version. :return: True if ver1 < ver2, else False. :rtype: bool",
"func":1
},
{
"ref":"modules.configuration.configuration_base.Type",
"url":71,
"doc":"Type of configuration."
},
{
"ref":"modules.configuration.configuration_base.Type.NONE",
"url":71,
"doc":""
},
{
"ref":"modules.configuration.configuration_base.Type.HTTP",
"url":71,
"doc":""
},
{
"ref":"modules.configuration.configuration_base.Type.SSL",
"url":71,
"doc":""
},
{
"ref":"modules.configuration.configuration_base.Config_base",
"url":71,
"doc":"Interface for configuration base."
},
{
"ref":"modules.configuration.configuration_base.Config_base.openSSL",
"url":71,
"doc":""
},
{
"ref":"modules.configuration.configuration_base.Config_base.VHOST_USE",
"url":71,
"doc":""
},
{
"ref":"modules.configuration.configuration_base.Config_base.condition",
"url":71,
"doc":"Dummy condition method. :param vhost: VirtualHost object. :type vhost: :class: ~letsencrypt_apache.obj.VirtualHost :returns: True if vhost is vulnerable. :rtype: bool :raise: NotImplementedError if method is not implemented.",
"func":1
},
{
"ref":"modules.configuration.configuration_base.Config_base.fix",
"url":71,
"doc":"Dummy fix method. :param vhost: VirtualHost object. :type vhost: :class: ~letsencrypt_apache.obj.VirtualHost :raise: NotImplementedError if method is not implemented.",
"func":1
},
{
"ref":"modules.configuration.configuration_base.Config_base.is_empty",
"url":71,
"doc":"Dummy empty method. :param vhost: VirtualHost object. :type vhost: :class: ~letsencrypt_apache.obj.VirtualHost :returns: True if vhost doesn't have the contextual VirtualHost directive. :rtype: bool :raise: NotImplementedError if method is not implemented.",
"func":1
},
{
"ref":"modules.configuration.configuration_base.Parse_configuration_protocols",
"url":71,
"doc":"Check if vhost is vulnerable to TLS SSLProtocol bad configuration. :param openssl: OpenSSL version. :type openssl: str :param protocols: TLS/SSL protocols to check. :type protocols: dict"
},
{
"ref":"modules.configuration.configuration_base.Parse_configuration_protocols.is_empty",
"url":71,
"doc":"Check if vhost doesn't have the contextual directive. :param vhost: VirtualHost object. :type vhost: :class: ~letsencrypt_apache.obj.VirtualHost :returns: True if vhost doesn't have the contextual directive. :rtype: bool",
"func":1
},
{
"ref":"modules.configuration.configuration_base.Parse_configuration_protocols.is_tls",
"url":71,
"doc":"Check if vhost is using only the TLS version x. :param vhost: VirtualHost object. :type vhost: :class: ~letsencrypt_apache.obj.VirtualHost :param version: TLS version to check. :type version: int :returns: True if vhost is using ONLY the TLS version x. :rtype: bool",
"func":1
},
{
"ref":"modules.configuration.configuration_base.Parse_configuration_protocols.fix",
"url":71,
"doc":"Fix TLS/SSL protocol bad configuration. :param vhost: VirtualHost object. :type vhost: :class: ~letsencrypt_apache.obj.VirtualHost ",
"func":1
},
{
"ref":"modules.configuration.configuration_base.Parse_configuration_protocols.condition",
"url":71,
"doc":"Check if vhost is vulnerable to TLS SSLProtocol bad configuration. :param vhost: VirtualHost object. :type vhost: :class: ~letsencrypt_apache.obj.VirtualHost :param openssl: OpenSSL version. :type openssl: str :param ignore_openssl: Ignore OpenSSL version. :type ignore_openssl: bool :returns: True if vhost is vulnerable to TLS SSLProtocol bad configuration. :rtype: bool",
"func":1
},
{
"ref":"modules.configuration.configuration_base.Parse_configuration_ciphers",
"url":71,
"doc":"Check if vhost is vulnerable to misconfigured TLS cipher."
},
{
"ref":"modules.configuration.configuration_base.Parse_configuration_ciphers.is_tls",
"url":71,
"doc":"Check if vhost is using ONLY the TLS version x. :param vhost: VirtualHost object. :type vhost: :class: ~letsencrypt_apache.obj.VirtualHost :param version: TLS version to check. :type version: int :returns: True if vhost is using ONLY the TLS version x. :rtype: bool",
"func":1
},
{
"ref":"modules.configuration.configuration_base.Parse_configuration_ciphers.is_empty",
"url":71,
"doc":"Check if vhost doesn't have the contextual directive. :param vhost: VirtualHost object. :type vhost: :class: ~letsencrypt_apache.obj.VirtualHost :returns: True if vhost doesn't have the contextual directive. :rtype: bool",
"func":1
},
{
"ref":"modules.configuration.configuration_base.Parse_configuration_ciphers.fix",
"url":71,
"doc":"Fix misconfigured TLS cipher in vhost. :param vhost: VirtualHost object. :type vhost: :class: ~letsencrypt_apache.obj.VirtualHost ",
"func":1
},
{
"ref":"modules.configuration.configuration_base.Parse_configuration_ciphers.condition",
"url":71,
"doc":"Check if vhost is vulnerable to misconfigured TLS cipher. :param vhost: VirtualHost object. :type vhost: :class: ~letsencrypt_apache.obj.VirtualHost :param openssl: OpenSSL version. :type openssl: str :param ignore_openssl: Ignore OpenSSL version. :type ignore_openssl: bool :returns: True if vhost is vulnerable to misconfigured TLS cipher. :rtype: bool",
"func":1
},
{
"ref":"modules.configuration.configuration_base.Parse_configuration_strict_security",
"url":71,
"doc":"Check if vhost is vulnerable to misconfigured TLS strict security."
},
{
"ref":"modules.configuration.configuration_base.Parse_configuration_strict_security.VHOST_USE",
"url":71,
"doc":""
},
{
"ref":"modules.configuration.configuration_base.Parse_configuration_strict_security.is_empty",
"url":71,
"doc":"Check if vhost doesn't have the header directive. :param vhost: VirtualHost object. :type vhost: :class: ~letsencrypt_apache.obj.VirtualHost :returns: True if vhost doesn't have the header directive. :rtype: bool",
"func":1
},
{
"ref":"modules.configuration.configuration_base.Parse_configuration_strict_security.fix",
"url":71,
"doc":"Fix misconfigured TLS strict security in vhost. :param vhost: VirtualHost object. :type vhost: :class: ~letsencrypt_apache.obj.VirtualHost ",
"func":1
},
{
"ref":"modules.configuration.configuration_base.Parse_configuration_strict_security.condition",
"url":71,
"doc":"Check if vhost is vulnerable to misconfigured TLS strict security. :param vhost: VirtualHost object. :type vhost: :class: ~letsencrypt_apache.obj.VirtualHost :param openssl: OpenSSL version. :type openssl: str :param ignore_openssl: Ignore OpenSSL version. :type ignore_openssl: bool :returns: True if vhost is vulnerable to misconfigured TLS strict security. :rtype: bool",
"func":1
},
{
"ref":"modules.configuration.configuration_base.Parse_configuration_checks_compression",
"url":71,
"doc":"Check if vhost is vulnerable to misconfigured TLS compression. :param vhost: VirtualHost object. :type vhost: :class: ~letsencrypt_apache.obj.VirtualHost "
},
{
"ref":"modules.configuration.configuration_base.Parse_configuration_checks_compression.VHOST_USE",
"url":71,
"doc":""
},
{
"ref":"modules.configuration.configuration_base.Parse_configuration_checks_compression.is_tls",
"url":71,
"doc":"Check if vhost is using only a specific version of TLS. :param vhost: VirtualHost object. :type vhost: :class: ~letsencrypt_apache.obj.VirtualHost :param version: TLS version. :type version: int :returns: True if vhost is using only a specific version of TLS. :rtype: bool",
"func":1
},
{
"ref":"modules.configuration.configuration_base.Parse_configuration_checks_compression.is_empty",
"url":71,
"doc":"Check if vhost doesn't have the SSLCompression directive. :param vhost: VirtualHost object. :type vhost: :class: ~letsencrypt_apache.obj.VirtualHost :returns: True if vhost doesn't have the SSLCompression directive. :rtype: bool",
"func":1
},
{
"ref":"modules.configuration.configuration_base.Parse_configuration_checks_compression.fix",
"url":71,
"doc":"Fix misconfigured TLS compression in vhost. :param vhost: VirtualHost object. :type vhost: :class: ~letsencrypt_apache.obj.VirtualHost ",
"func":1
},
{
"ref":"modules.configuration.configuration_base.Parse_configuration_checks_compression.condition",
"url":71,
"doc":"Check if vhost is vulnerable to misconfigured TLS compression. :param vhost: VirtualHost object. :type vhost: :class: ~letsencrypt_apache.obj.VirtualHost :param openssl: OpenSSL version. :type openssl: str :param ignore_openssl: Ignore OpenSSL version. :type ignore_openssl: bool :returns: True if vhost is vulnerable to misconfigured TLS compression. :rtype: bool",
"func":1
},
{
"ref":"modules.configuration.configuration_base.Parse_configuration_checks_redirect",
"url":71,
"doc":"Check if vhost is vulnerable to misconfigured TLS redirect."
},
{
"ref":"modules.configuration.configuration_base.Parse_configuration_checks_redirect.VHOST_USE",
"url":71,
"doc":""
},
{
"ref":"modules.configuration.configuration_base.Parse_configuration_checks_redirect.is_empty",
"url":71,
"doc":"Check if vhost doesn't have the RewriteEngine and RewriteRule directives. :param vhost: VirtualHost object. :type vhost: :class: ~letsencrypt_apache.obj.VirtualHost :returns: True if vhost doesn't have the RewriteEngine and RewriteRule directives. :rtype: bool",
"func":1
},
{
"ref":"modules.configuration.configuration_base.Parse_configuration_checks_redirect.fix",
"url":71,
"doc":"Fix misconfigured TLS redirect in vhost. :param vhost: VirtualHost object. :type vhost: :class: ~letsencrypt_apache.obj.VirtualHost ",
"func":1
},
{
"ref":"modules.configuration.configuration_base.Parse_configuration_checks_redirect.condition",
"url":71,
"doc":"Check if vhost is vulnerable to misconfigured TLS redirect. :param vhost: VirtualHost object. :type vhost: :class: ~letsencrypt_apache.obj.VirtualHost :param openssl: OpenSSL version. :type openssl: str :param ignore_openssl: Ignore OpenSSL version. :type ignore_openssl: bool :returns: True if vhost is vulnerable to misconfigured TLS redirect. :rtype: bool",
"func":1
},
{
"ref":"modules.configuration.configuration",
"url":72,
"doc":""
},
{
"ref":"modules.configuration.configuration.Configuration",
"url":72,
"doc":"Apache/Nginx configuration file parser :param path: path to the configuration file :type path: str :param type_: Type of the configuration file. :type type_: Type :param port: port to use for the check. :type port: str"
},
{
"ref":"modules.configuration.configuration.Configuration.Type",
"url":72,
"doc":"Enum for configuration file types"
},
{
"ref":"modules.configuration.configuration.Configuration.get_path",
"url":72,
"doc":"",
"func":1
},
{
"ref":"modules.configuration.configuration.Configuration.is_vuln",
"url":72,
"doc":"Checks if the configuration is vulnerable. :param modules: modules to check :type modules: dict :param openssl: openssl version to use :type openssl: str :param ignore_openssl: ignore openssl version :type ignore_openssl: bool :return: True if the configuration is vulnerable :rtype: bool",
"func":1
},
{
"ref":"modules.configuration.configuration.Configuration.fix",
"url":72,
"doc":"Fixes the configuration. :param modules: modules to check :type modules: dict :param openssl: openssl version to use :type openssl: str :param ignore_openssl: ignore openssl version :type ignore_openssl: bool :param online: check online :type online: bool",
"func":1
},
{
"ref":"modules.configuration.configuration.Configuration.save",
"url":72,
"doc":"Saves the configuration. :param file_name: file name to save, if None, the input file name is used :type file_name: str :default file_name: None",
"func":1
},
{
"ref":"modules.report",
"url":73,
"doc":""
},
{
"ref":"modules.report.Report",
"url":73,
"doc":"Output Module that generates the report."
},
{
"ref":"modules.report.Report.Mode",
"url":73,
"doc":"Enum for the report mode."
},
{
"ref":"modules.report.Report.input",
"url":73,
"doc":"Input function for the Report module. :param kwargs: Arguments for the Report module. See below. :type kwargs: dict :Keyword Arguments:   results (dict)  Dictionary containing the results of the scan.   path (string)  Path to the report.   mode (Mode)  Report mode.   stix (bool)  If True, the report will be in STIX format.",
"func":1
},
{
"ref":"modules.report.Report.run",
"url":73,
"doc":"Runs the report. :param kwargs: Arguments for the Report module. See below. :type kwargs: dict :Keyword Arguments:   results (dict)  Dictionary containing the results of the scan.   path (string)  Path to the report.   mode (Mode)  Report mode.   stix (bool)  If True, the report will be generated in STIX format.",
"func":1
}
]