import itertools
import json
import os.path
import re
from pathlib import Path

from modules.compliance.configuration.apache_configuration import ApacheConfiguration
from modules.compliance.configuration.configuration_base import ConfigurationMaker
from modules.compliance.configuration.nginx_configuration import NginxConfiguration
from modules.compliance.wrappers.certificateparser import CertificateParser
from modules.compliance.wrappers.conditionparser import ConditionParser
from modules.compliance.wrappers.db_reader import Database
from modules.configuration.configuration_base import OpenSSL
from modules.server.wrappers.testssl import Testssl
from utils.database import get_standardized_level
from utils.loader import load_configuration
from utils.logger import Logger
from utils.mitigations import MitigationLoader
from utils.validation import Validator


def convert_signature_algorithm(sig_alg: str) -> str:
    """
    This function is needed to convert the input from testssl to make it compatible with the requirements database
    """
    if "RSA+" in sig_alg:
        sig_alg = sig_alg.replace("RSA+", "rsa_pkcs1_")
    sig_alg = sig_alg.replace("-", "_").replace("+", "_").lower()
    if "brainpool" in sig_alg:
        hash_len = sig_alg[-3:]
        sig_alg = sig_alg.replace("brainpool", f"brainpoolP{hash_len}r1tls13")
    elif "ecdsa" in sig_alg:
        hash_len = sig_alg[-3:]
        sig_alg = sig_alg.replace("ecdsa", f"ecdsa_secp{hash_len}r1")
    return sig_alg


class Compliance:
    report_config = load_configuration("special_configs", "configs/compliance/")

    def __init__(self):
        self.hostname = ""
        self._openssl_version = ""
        self._custom_guidelines = None
        self._apache = True
        # legacy vs security level switch
        self._security = True
        self._input_dict = {}
        self._database_instance = Database()
        self._logging = Logger("Compliance module")
        self._last_data = {}
        self._output_dict = {}
        self._user_configuration = {}
        self.entries = {}
        self.evaluated_entries = {}
        self._certificate_index = "1"
        self.evaluations_mapping = load_configuration("evaluations_mapping", "configs/compliance/")
        self.sheet_columns = load_configuration("sheet_columns", "configs/compliance/")
        self.misc_fields = load_configuration("misc_fields", "configs/compliance/")
        self._validator = Validator()
        self._condition_parser = ConditionParser(self._user_configuration)
        self.test_ssl = Testssl()
        self._config_class = None
        self._database_instance.input(["Guideline"])
        self._guidelines = [name[0].upper() for name in self._database_instance.output()]
        self._alias_parser = AliasParser()
        self._certificate_parser = CertificateParser()
        self._cert_sig_algs = [el[0] for el in self._database_instance.run(tables=["CertificateSignature"],
                                                                           columns=["name"])]
        self._configuration_maker = ConfigurationMaker("apache", self._openssl_version)
        self._openssl = OpenSSL()
        self._ciphers_converter = load_configuration("openssl_to_iana", "configs/compliance/")
        self._user_configuration_types = load_configuration("user_conf_types", "configs/compliance/generate/")
        self._type_converter = {
            "dict": dict,
            "list": list,
            "set": set,
        }
        # This is used in the check_year function to disable entries that are not valid anymore
        self.level_flipper = {
            "must": "must not",
            "recommended": "not recommended"
        }

    def level_to_use(self, levels):
        """
        Given two evaluations returns true if the first one wins, false otherwise.

        :param levels: list of evaluations to be checked
        :type levels: list
        :return: the standard which wins
        :rtype: int
        """
        # If a level is not mapped it can be considered as a Not mentioned
        security_mapping = "security" if self._security else "legacy"
        if not levels:
            raise IndexError("Levels list is empty")
        first_value = self.evaluations_mapping.get(security_mapping, {}).get(get_standardized_level(levels[0]), 4)
        best = 0
        for i, el in enumerate(levels[1:]):
            evaluation_value = self.evaluations_mapping.get(security_mapping, {}).get(get_standardized_level(el), 4)
            if first_value > evaluation_value:
                # +1 is needed because the first element is ignored
                best = i + 1
        # if they have the same value first wins
        return best

    def input(self, **kwargs):
        """
        Set the input parameters

        :param kwargs: input parameters
        :type kwargs: dict

        :Keyword Arguments:
            * *guidelines* (``str``) -- string containing the names of the guidelines that should be checked in the form: guideline_version1_version2 in the case of multiple guidelines they should be comma separated
            * *actual_configuration_path* (``str``) -- The configuration to check, not needed if generating
            * *hostname* (``str``) -- Hostname on which testssl should be used
            * *apache* (``bool``) -- Default to True, if false nginx will be used
            * *config_output* (``str``) -- The path and name of the output file
            * *custom_guidelines* (``dict``) -- dictionary with form: { sheet : {guideline: name: {"level":level}}
        """
        actual_configuration = kwargs.get("actual_configuration_path")
        port = kwargs.get("port", "")
        if port:
            port = ":" + port
        self.hostname = kwargs.get("hostname") + port
        self._apache = kwargs.get("apache", True)
        self._security = kwargs.get("security", True)
        output_file = kwargs.get("output_config")
        custom_guidelines = kwargs.get("custom_guidelines")
        if custom_guidelines:
            if not os.path.isfile(self._custom_guidelines):
                raise FileNotFoundError(f"Custom guidelines file {self._custom_guidelines} not found")
            with open(custom_guidelines, "r") as f:
                self._custom_guidelines = json.load(f)

        guidelines_string = kwargs.get("guidelines")
        openssl_version = kwargs.get("openssl_version")
        ignore_openssl = kwargs.get("ignore_openssl")
        self._certificate_index = kwargs.get("certificate_index", "1")

        if isinstance(self._certificate_index, int):
            self._certificate_index = str(self._certificate_index)
        if ignore_openssl[0]:
            self._openssl_version = "1.1.1"
        elif openssl_version:
            self._openssl_version = openssl_version[0]
        if self._openssl_version not in self._configuration_maker.signature_algorithms:
            self._logging.warning(f"OpenSSL version {openssl_version[0]} is not supported, using 1.1.1")
            self._openssl_version = "1.1.1"
        self._configuration_maker.set_openssl_version(self._openssl_version)

        # guidelines evaluation
        self._validator.string(guidelines_string)
        guidelines_list = guidelines_string.split(",") if "," in guidelines_string else [guidelines_string]
        sheets_to_check = self._alias_parser.get_sheets_to_check(guidelines_list)
        self._validator.dict(sheets_to_check)

        if actual_configuration and self._validator.string(actual_configuration):
            try:
                self._config_class = ApacheConfiguration(actual_configuration)
            except Exception as e:
                self._logging.debug(
                    f"Couldn't parse config as apache: {e}\ntrying with nginx..."
                )
                self._config_class = NginxConfiguration(actual_configuration)
            self.prepare_configuration(self._config_class.configuration)
        if self.hostname and self._validator.string(self.hostname) and self.hostname != "placeholder":
            if os.path.isfile(f"testssl_dumps/testssl_output-{self.hostname}.json"):
                with open(f"testssl_dumps/testssl_output-{self.hostname}.json", "r") as f:
                    test_ssl_output = json.load(f)
            else:
                test_ssl_output = self.test_ssl.run(**{"hostname": self.hostname, "one": True})
            with open(f"testssl_dumps/testssl_output-{self.hostname}.json", "w") as f:
                json.dump(test_ssl_output, f, indent=4)
            failed = 0
            for key in test_ssl_output:
                if test_ssl_output[key].get("scanProblem") and test_ssl_output[key]["scanProblem"].get(
                        "severity") == "FATAL":
                    failed += 1
                    self._logging.warning(f"Testssl failed to perform the analysis on {key}")
            if failed == len(test_ssl_output):
                self._output_dict[self.hostname] = {"error": "Testssl failed to perform the analysis"}
            self.prepare_testssl_output(test_ssl_output)
        if output_file and self._validator.string(output_file):
            if self._apache:
                self._config_class = ApacheConfiguration()
            else:
                self._config_class = NginxConfiguration()
            self._config_class.set_out_file(Path(output_file))
        self._input_dict = kwargs
        self._input_dict["sheets_to_check"] = sheets_to_check

    # To override
    def _worker(self, sheets_to_check, hostname):
        """
        :param sheets_to_check: dict of sheets that should be checked in the form: sheet:{protocol, version_of_protocol}
        :type sheets_to_check: dict

        :return: processed results
        :rtype: dict

        :raise  NotImplementedError:
        """
        raise NotImplementedError("This method should be reimplemented")

    def run(self, **kwargs):
        self.input(**kwargs)
        self._worker(self._input_dict["sheets_to_check"], self.hostname)
        return self.output()

    def output(self):
        if not self._output_dict[self.hostname].get("error"):
            self.prune_output()
            self._prepare_output()
        return self._output_dict.copy()

    def _prepare_output(self):
        for hostname in self._output_dict:
            for sheet in self._output_dict[hostname]:
                mitigation = MitigationLoader().load_mitigation("Compliance_" + sheet)
                guidelines = ", ".join(self._output_dict[hostname][sheet]["guidelines"])
                mitigation["Entry"]["Description"] = mitigation["Entry"]["Description"].format(sheet=sheet,
                                                                                               guidelines=guidelines)
                textual = mitigation["Entry"]["Mitigation"]["Textual"]
                total_string_apache = total_string_nginx = "<code>"
                conf_instructions = mitigation["#ConfigurationInstructions"]
                if self._output_dict[hostname][sheet]["entries_add"]:
                    add_string = "<br/>-{name} {action} according to {source}"
                    add_list = []
                    total_string_apache, total_string_nginx = self.format_output_string(add_string, hostname, sheet,
                                                                                        conf_instructions,
                                                                                        total_string_apache,
                                                                                        total_string_nginx,
                                                                                        "entries_add", add_list)
                    # this is necessary to avoid having an extra empty line
                    textual = textual.format(add=";".join(add_list), remove="{remove}", notes="{notes}")
                else:
                    # remove the line that contains {add}
                    lines = textual.split("<br/>")
                    textual = "<br/>".join([line for line in lines if "{add}" not in line])
                if self._output_dict[hostname][sheet].get("only_total_string_add"):
                    # remove the first line from Textual
                    lines = textual.split("<br/>")
                    textual = "<br/>".join(lines[1:])
                if self._output_dict[hostname][sheet]["entries_remove"]:
                    remove_string = "<br/>-{name} {action} according to {source}"
                    remove_list = []
                    total_string_apache, total_string_nginx = self.format_output_string(remove_string, hostname, sheet,
                                                                                        conf_instructions,
                                                                                        total_string_apache,
                                                                                        total_string_nginx,
                                                                                        "entries_remove", remove_list)
                    textual = textual.replace("{add}<br/>{remove}", "{add}{remove}")
                    textual = textual.format(remove=";".join(remove_list), notes="{notes}")
                else:
                    # remove the line that contains {remove}
                    lines = textual.split("<br/>")
                    textual = "<br/>".join([line for line in lines if "{remove}" not in line])
                if self._output_dict[hostname][sheet]["notes"]:
                    notes_string = "<br/>{name}"
                    notes_list = []
                    total_string_apache, total_string_nginx = self.format_output_string(notes_string, hostname, sheet,
                                                                                        conf_instructions,
                                                                                        total_string_apache,
                                                                                        total_string_nginx,
                                                                                        "notes", notes_list)
                    textual = textual.format(notes=";".join(notes_list))
                else:
                    # remove the line that contains {notes}
                    lines = textual.split("<br/>")
                    textual = "<br/>".join([line for line in lines if "{notes}" not in line])
                textual = textual.replace(":<br/><br/>", ":<br/>", 1)
                mitigation["Entry"]["Mitigation"]["Textual"] = textual
                if total_string_apache != "<code>":
                    if conf_instructions["mode"] == "standard":
                        total_string_apache += "</code>"
                    else:
                        total_string_apache = total_string_apache.replace("<code>", "", 1)
                    mitigation["Entry"]["Mitigation"]["Apache"] = mitigation["Entry"]["Mitigation"]["Apache"].format(
                        total_string=total_string_apache)
                if total_string_nginx != "<code>":
                    if conf_instructions["mode"] == "standard":
                        total_string_nginx += "</code>"
                    else:
                        total_string_nginx = total_string_nginx.replace("<code>", "", 1)
                    mitigation["Entry"]["Mitigation"]["Nginx"] = mitigation["Entry"]["Mitigation"]["Nginx"].format(
                        total_string=total_string_nginx)
                # TODO clean the dictionary before adding mitigation
                if conf_instructions.get("openssl_dependency"):
                    for version in conf_instructions["openssl_dependency"]:
                        operator, check_version = version.split(" ")
                        add_openssl_text = False
                        if operator == "<" and self._openssl.less_than(self._openssl_version, check_version):
                            add_openssl_text = True
                        elif operator == ">" and self._openssl.greater_than(self._openssl_version, check_version):
                            add_openssl_text = True
                        if add_openssl_text:
                            mitigation["Entry"]["Mitigation"]["Textual"] += conf_instructions["openssl_dependency"][
                                version].get("Textual", "")
                            mitigation["Entry"]["Mitigation"]["Apache"] += conf_instructions["openssl_dependency"][
                                version].get("Apache", "")
                            mitigation["Entry"]["Mitigation"]["Nginx"] += conf_instructions["openssl_dependency"][
                                version].get("Nginx", "")
                self._output_dict[hostname][sheet]["mitigation"] = mitigation

    def format_output_string(self, string, hostname, sheet, conf_instructions, total_string_apache, total_string_nginx,
                             entries_key, strings_list):
        source = ""
        for entry in self._output_dict[hostname][sheet][entries_key]:
            source = self._output_dict[hostname][sheet][entry]["source"]
            entry_name, _ = self._configuration_maker.perform_post_actions(conf_instructions, entry, source)
            level = self._output_dict[hostname][sheet][entry]["level"].lower()
            if conf_instructions["mode"] == "standard":
                # The usage of post actions is needed to fix the entries of some of the sheets
                total_string_apache += conf_instructions["connector"] + conf_instructions[level].replace("name",
                                                                                                         entry_name)
                total_string_nginx += conf_instructions["connector"] + conf_instructions[level].replace("name",
                                                                                                        entry_name)
            if not self._output_dict[hostname][sheet][entry].get("total_string_only"):
                if conf_instructions["mode"] == "specific_mitigation":
                    string = conf_instructions.get(entry, "")
                    if conf_instructions.get(entry + "_config"):
                        total_string_apache += "<br/>" + conf_instructions[entry + "_config"]["Apache"]
                        total_string_nginx += "<br/>" + conf_instructions[entry + "_config"]["Nginx"]

                # This case is needed because the notes don't have the action and source fields
                if entries_key == "notes":
                    if "{action}" in string:
                        string = string.split("{action}")[0].strip()
                    tmp_string = string.format(name=entry_name)
                else:
                    tmp_string = string.format(name=entry_name,
                                               action=self._output_dict[hostname][sheet][entry]["action"],
                                               source=self._output_dict[hostname][sheet][entry]["source"])
                if self._output_dict[hostname][sheet][entry].get("notes"):
                    tmp_string += "; " + self._output_dict[hostname][sheet][entry]["notes"]
                tmp_string, _ = self._configuration_maker.perform_post_actions(conf_instructions, tmp_string, source)
                strings_list.append(tmp_string)
        total_string_apache, _ = self._configuration_maker.perform_post_actions(conf_instructions, total_string_apache,
                                                                                source,
                                                                                "actions_on_final_string")
        total_string_nginx, _ = self._configuration_maker.perform_post_actions(conf_instructions, total_string_nginx,
                                                                               source,
                                                                               "actions_on_final_string")

        connector = conf_instructions.get("connector", None)
        if connector:
            connector_length = len(connector)
            # the 6 is added because total_string starts with <code>
            if total_string_apache[6:connector_length + 6] == conf_instructions["connector"]:
                total_string_apache = total_string_apache.replace(conf_instructions["connector"], "", 1)
            if total_string_nginx[6:connector_length + 6] == conf_instructions["connector"]:
                total_string_nginx = total_string_nginx.replace(conf_instructions["connector"], "", 1)
        return total_string_apache, total_string_nginx

    def prune_output(self):
        to_remove = set()
        remove_sheets = set()
        for hostname in self._output_dict:
            for sheet in self._output_dict[hostname]:
                for note in self._output_dict[hostname][sheet]["notes"]:
                    if not self._output_dict[hostname][sheet][note].get("notes") or \
                            note in self._output_dict[hostname][sheet]["entries_add"] or note in \
                            self._output_dict[hostname][sheet]["entries_remove"]:
                        to_remove.add(note)
                count = 0

                for entry in self._output_dict[hostname][sheet]["entries_add"]:
                    if self._output_dict[hostname][sheet][entry].get("total_string_only"):
                        count += 1
                if count == len(self._output_dict[hostname][sheet]["entries_add"]):
                    self._output_dict[hostname][sheet]["only_total_string_add"] = True

                for entry in to_remove:
                    if entry not in self._output_dict[hostname][sheet]["entries_add"] and entry not in \
                            self._output_dict[hostname][sheet]["entries_remove"]:
                        del self._output_dict[hostname][sheet][entry]
                    self._output_dict[hostname][sheet]["notes"].remove(entry)
                to_remove = set()
                no_add = self._output_dict[hostname][sheet]["entries_add"].__len__() == 0 or \
                         self._output_dict[hostname][sheet].get("only_total_string_add")
                if no_add and not \
                        self._output_dict[hostname][sheet]["entries_remove"] and not \
                        self._output_dict[hostname][sheet]["notes"]:
                    remove_sheets.add(sheet)
            for sheet in remove_sheets:
                del self._output_dict[hostname][sheet]

    def _add_certificate_signature_algorithm(self, alg):
        """
        Adds the passed algorithm to the CertificateSignature field after parsing it.
        :param alg: the algorithm to add
        :return: a list containing the parsed algorithms
        """
        to_return = []
        if isinstance(alg, str):
            alg = [alg]

        for sig_alg in alg:
            sig_alg = sig_alg.replace("RSASSA-PSS", "RSA")
            if sig_alg.lower() not in self._cert_sig_algs:
                sig_alg = "anonymous"
            to_return.append(sig_alg)
            self._user_configuration["CertificateSignature"].add(sig_alg.lower())
        return to_return

    def prepare_configuration(self, actual_configuration):
        for field in actual_configuration:
            new_field = actual_configuration[field]
            if isinstance(new_field, str):
                if "Cipher" in field:
                    new_field = new_field.split(":") if ":" in new_field else new_field
                elif "Protocol" in field and " " in new_field:
                    tmp_dict = {}
                    for version in new_field.split(" "):
                        accepted = False if version[0] == '-' else True
                        new_version_name = version.replace("-", "").replace("v", " ")
                        if new_version_name[-2] != '.' and new_version_name != "all":
                            new_version_name += ".0"
                        tmp_dict[new_version_name] = accepted
                    new_field = tmp_dict
            field_name = self._config_class.reverse_mapping.get(field, field)
            self._user_configuration[field_name] = new_field

    @staticmethod
    def find_cert_index(field: str):
        if "#" in field:
            # In the case of multiple certificates the intermediate certificates have 2 numbers
            groups = re.match(r".*(\d+).*(\d)|.*(\d+)", field).groups()
            groups = [el for el in groups if el]
            return "_".join(groups)
        else:
            return "1"

    def prepare_testssl_output(self, test_ssl_output):
        # all the necessary field are initialized here
        for field in self._user_configuration_types:
            data_structure = self._user_configuration_types.get(field)
            # this final step is needed to convert from string to data_structure
            # by using a dict is possible avoid using eval
            self._user_configuration[field] = self._type_converter.get(data_structure, dict)()

        for site in test_ssl_output:
            for field in test_ssl_output[site]:
                actual_dict = test_ssl_output[site][field]
                # Each protocol has its own field
                if (field.startswith("SSL") or field.startswith("TLS")) and field[3] != "_":
                    # Standardization to have it compliant with the database
                    new_version_name = field.replace("_", ".").replace("v", " ").replace("TLS1", "TLS 1")
                    if new_version_name[-2] != '.':
                        new_version_name += ".0"
                    # The protocols may appear both as supported and not supported, so they are saved in a dictionary
                    # with a boolean associated to the protocol to know if it is supported or not
                    self._user_configuration["Protocol"][new_version_name] = "not" not in actual_dict["finding"]

                # All the ciphers appear in different fields whose form is cipher_%x%
                elif field.startswith("cipher") and "x" in field:
                    value = actual_dict.get("finding", "")
                    if " " in value:
                        # Only the last part of the line is the actual cipher
                        value = value.split(" ")[-1]
                        value = self._ciphers_converter.get(value, value)
                        self._user_configuration["CipherSuite"].add(value)

                elif field == "FS_ciphers":
                    value = actual_dict.get("finding", "")
                    if " " in value:
                        for cipher in value.split(" "):
                            # Only the last part of the line is the actual cipher
                            cipher = self._ciphers_converter.get(cipher, cipher)
                            self._user_configuration["CipherSuite"].add(cipher)
                    else:
                        cipher = self._ciphers_converter.get(value, value)
                        self._user_configuration["CipherSuite"].add(cipher)

                elif field == "TLS_extensions":
                    entry = actual_dict["finding"]
                    entry = entry.replace("' '", ",").replace("'", "")
                    extensions: list = entry.split(",")
                    extensions_pairs = {}
                    for ex in extensions:
                        # the [1] is the iana code
                        tokens = ex.split("/#")
                        extensions_pairs[tokens[1]] = tokens[0].lower().replace(" ", "_")
                    self._user_configuration["Extension"] = extensions_pairs

                # From the certificate signature algorithm is possible to extract both CertificateSignature and Hash
                elif field.startswith("cert_Algorithm") or field.startswith("cert_signatureAlgorithm"):
                    if " " in actual_dict["finding"]:
                        tokens = actual_dict["finding"].split(" ")
                        sig_alg = tokens[-1]
                        hash_alg = tokens[0]
                        # sometimes the hashing algorithm comes first, so they must be switched
                        if sig_alg.startswith("SHA"):
                            sig_alg, hash_alg = hash_alg, sig_alg
                        sig_alg = self._add_certificate_signature_algorithm(sig_alg)[0]
                        self._user_configuration["Hash"].add(hash_alg.lower())
                        cert_index = self.find_cert_index(field)
                        if not self._user_configuration["Certificate"].get(cert_index):
                            self._user_configuration["Certificate"][cert_index] = {}
                        self._user_configuration["Certificate"][cert_index]["SigAlg"] = sig_alg

                elif field.startswith("cert_keySize"):
                    # the first two tokens (after doing a space split) are the Key Algorithm and its key size
                    element_to_add = actual_dict["finding"].split(" ")[:2]
                    element_to_add[1] = int(element_to_add[1])
                    self._user_configuration["KeyLengths"].add(tuple(element_to_add))
                    cert_index = self.find_cert_index(field)
                    if not self._user_configuration["Certificate"].get(cert_index):
                        self._user_configuration["Certificate"][cert_index] = {}
                    self._user_configuration["Certificate"][cert_index]["KeyAlg"] = element_to_add[0]
                elif field == "DH_groups":
                    curve, length = re.match(r"([^\d]+)(\d+)", actual_dict["finding"]).groups()
                    if "(" in actual_dict["finding"]:
                        self._user_configuration["KeyLengths"].add(("DH", int(length)))
                    else:
                        self._user_configuration["KeyLengths"].add(("DH", int(length)))
                        self._user_configuration["Groups"].append(actual_dict["finding"])

                # The field FS_TLS_12_sig_algs contains the signature algorithms that can be used for Forward secrecy.
                # For more details https://github.com/drwetter/testssl.sh/issues/2440
                elif field[-11:] == "12_sig_algs":
                    finding = actual_dict["finding"]
                    elements = finding.split(" ") if " " in finding else [finding]
                    hashes = []
                    signatures = []
                    for el in elements:
                        # The ones with the '-' inside are the ones for TLS 1.3.
                        if "-" not in el and "+" in el:
                            # The entries are SigAlg+HashAlg
                            tokens = el.split("+")
                            # RSASSA-PSS is a subset of RSA
                            hashes.append(tokens[1].lower())
                        signatures.append(convert_signature_algorithm(el))
                    # self._add_certificate_signature_algorithm(signatures)
                    self._user_configuration["Hash"].update(hashes)
                    self._user_configuration["Signature"].update(signatures)

                # From TLS 1.3 the signature algorithms are different from the previous versions.
                # So they are saved in a different field of the configuration dictionary.
                elif field[-11:] == "13_sig_algs":
                    finding = actual_dict["finding"]
                    values = finding.split(" ") if " " in finding else [finding]
                    values = [convert_signature_algorithm(sig) for sig in values]
                    self._user_configuration["Signature"].update(values)

                # The supported groups are available as a list in this field
                elif field[-12:] == "ECDHE_curves":
                    values = actual_dict["finding"].split(" ") if " " in actual_dict["finding"] \
                        else [actual_dict["finding"]]
                    # secp256r1 is the same as prime256v1, it also happens with the 192 version
                    values = [re.sub(r"prime(\d+)v1", r"secp\1r1", val) for val in values]
                    self._user_configuration["Groups"] = values

                # The transparency field describes how the transparency is handled in each certificate.
                # https://developer.mozilla.org/en-US/docs/Web/Security/Certificate_Transparency (for the possibilities)
                elif "transparency" in field:
                    # the index is basically the certificate number
                    index = self.find_cert_index(field)
                    self._user_configuration["Transparency"][index] = actual_dict["finding"]

                elif field.startswith("cert_chain_of_trust"):
                    # the index is basically the certificate number
                    index = self.find_cert_index(field)
                    self._user_configuration["TrustedCerts"][index] = actual_dict["finding"]

                elif (field == "cert" or re.match(r"cert <(?:cert|hostCert)#\d+>", field)) or \
                        (field == "intermediate_cert" or re.match(r"intermediate_cert <#\d+>", field)):

                    cert_index = self.find_cert_index(field)
                    if field.startswith("int"):
                        cert_index = "int_" + cert_index
                    if not self._user_configuration["Certificate"].get(cert_index):
                        self._user_configuration["Certificate"][cert_index] = {}
                    if not self._user_configuration["CertificateExtensions"].get(cert_index):
                        self._user_configuration["CertificateExtensions"][cert_index] = {}
                    cert_data = self._certificate_parser.run(actual_dict["finding"])
                    for entry in cert_data:
                        if entry == "Extensions":
                            self._user_configuration["CertificateExtensions"][cert_index] = cert_data[entry]
                        else:
                            self._user_configuration["Certificate"][cert_index][entry] = cert_data[entry]

                elif field in self.misc_fields:
                    self._user_configuration["Misc"][self.misc_fields[field]] = "not" not in actual_dict["finding"]
                elif field == "fallback_SCSV":
                    self._user_configuration["fallback_SCSV"] = actual_dict["finding"]

    def update_result(self, sheet, name, entry_level, enabled, source, valid_condition, hostname):
        information_level = None
        action = None
        entry_level = get_standardized_level(entry_level) if entry_level else None
        total_string_only = False
        # print(f"{sheet} - {name} - {entry_level} - {enabled} - {source} - {valid_condition}")
        if entry_level == "must" and valid_condition and not enabled:
            information_level = "MUST"
            action = "has to be enabled"
        elif (entry_level in ["must", "recommended"] and enabled and valid_condition and
              sheet in self.report_config.get("has_total_string", [])):
            # these entries are not added to the output dict
            total_string_only = sheet in Compliance.report_config.get("has_total_string", [])
            information_level = "MUST"
            action = "has to be enabled"
        elif entry_level == "must not" and valid_condition and enabled:
            information_level = "MUST NOT"
            action = "has to be disabled"
        elif entry_level == "recommended" and valid_condition and not enabled:
            information_level = "RECOMMENDED"
            action = "should be enabled"
        elif (entry_level in ["must", "recommended"] and not valid_condition and
              sheet in self.report_config.get("has_specific_textual", [])):
            information_level = entry_level.lower()
            # The action does not matter in this case
            action = "should be enabled" if information_level == "recommended" else "has to be enabled"
        elif entry_level == "not recommended" and valid_condition and enabled:
            information_level = "NOT RECOMMENDED"
            action = "should be disabled"
        if not self._output_dict.get(hostname):
            self._output_dict[hostname] = {}
        if not self._output_dict[hostname].get(sheet):
            self._output_dict[hostname][sheet] = {
                "entries_add": [],
                "entries_remove": [],
                "notes": []
            }
        if information_level:
            if entry_level in ["must", "recommended"]:
                self._output_dict[hostname][sheet]["entries_add"].append(name)
            elif entry_level in ["must not", "not recommended"]:
                self._output_dict[hostname][sheet]["entries_remove"].append(name)
            self._output_dict[hostname][sheet][name] = {
                "level": information_level,
                "action": action,
                "source": source,
                "total_string_only": total_string_only
            }
        elif name not in self._output_dict[hostname][sheet]:
            self._output_dict[hostname][sheet][name] = {
                "level": "INFO",
                "action": "NOTE: ",
                "source": source,
            }
            self._output_dict[hostname][sheet]["notes"].append(name)
        if not self._output_dict[hostname][sheet].get("guidelines"):
            self._output_dict[hostname][sheet]["guidelines"] = set()
        self._output_dict[hostname][sheet]["guidelines"].add(source)

    def add_conditional_notes(self, enabled, valid_condition):
        conditional_notes = "\nNOTE: "
        for entry in self._condition_parser.entry_updates.keys():
            if entry.startswith("note_"):
                notes = self._condition_parser.entry_updates.get(entry)
                note_type = entry.split("_")[1]
                if note_type == "enabled" and enabled:
                    conditional_notes += "\n".join(notes)
                elif note_type == "disabled" and not enabled:
                    conditional_notes += "\n".join(notes)
                elif note_type == "true" and valid_condition:
                    conditional_notes += "\n".join(notes)
                elif note_type == "false" and not valid_condition:
                    conditional_notes += "\n".join(notes)
        if len(conditional_notes) == 7:
            conditional_notes = ""
        return conditional_notes

    def _retrieve_entries(self, sheets_to_check, columns):
        """
        Given the input dictionary and the list of columns updates the entries field with a dictionary in the form
        sheet: data. The data is ordered by name
        """
        self._logging.info("Retrieving entries from database")
        entries = {}
        tables = []
        for sheet in sheets_to_check:
            columns_to_get = []
            columns_to_use = self.sheet_columns.get(sheet, {"columns": columns})["columns"]
            if not self._output_dict.get(sheet):
                self._output_dict[sheet] = {}
            for guideline in sheets_to_check[sheet]:
                if guideline.upper() in self._guidelines:
                    table_name = self._database_instance.get_table_name(sheet, guideline,
                                                                        sheets_to_check[sheet][guideline])
                    tables.append(table_name)
            for t in tables:
                for column in columns_to_use:
                    # all the columns are repeated to make easier index access later
                    columns_to_get.append(f"{t}.{column}")

            join_condition = "ON {first_table}.id == {table}.id".format(first_table=tables[0], table="{table}")
            self._database_instance.input(tables, join_condition=join_condition)
            data = self._database_instance.output(columns_to_get)
            entries[sheet] = data
            tables = []
        self.entries = entries

    def _evaluate_entries(self, sheets_to_check, original_columns):
        """
        This function checks the entries with the same name and chooses which guideline to follow for that entry.
        The results can be found in the evaluated_entries field. The dictionary will have form:
        self.evaluated_entries[sheet][count] = {
                        "name": str, The name of the entry
                        "level": str, The level that resulted from the evaluation
                        "source": str, The guideline from which the level is deducted
                        "enabled": bool, If the entry is enabled in the configuration,
                        "valid_condition": bool, If the condition is valid or not
                        "note": str, Eventual note
                    }
        :param sheets_to_check: The input dictionary
        :param columns: columns used to retrieve data from database
        :type columns: list
        """
        # The entry is composed of all the columns repeated n times, with n being the number of guidelines.
        # The step is the number of columns. This allows easy data retrieval by doing something like:
        # "value_index * step * guideline_index" to retrieve data for a specific guideline
        for sheet in self.entries:
            columns = self.sheet_columns.get(sheet, {"columns": original_columns})["columns"]
            guideline_index = columns.index("guidelineName")
            # A more fitting name could be current_requirement_level
            level_index = columns.index("level")
            name_index = columns.index("name")
            condition_index = columns.index("condition")
            # this variable is needed to get the relative position of the condition in respect of the level
            level_to_condition_index = condition_index - level_index
            # this variable is needed to get the relative position of the guideline in respect of the level
            level_to_guideline_index = guideline_index - level_index
            step = len(columns)
            entries = self.entries[sheet]
            if not self.evaluated_entries.get(sheet):
                self.evaluated_entries[sheet] = {}
            custom_guidelines_list = sheets_to_check[sheet].keys() - self._guidelines
            total = 0
            for entry in entries:
                # These three are lists and not a single dictionary because the function level_to_use takes a list
                conditions = []
                levels = []
                # list holding all the notes so that a note gets displayed only if needed
                notes = []
                name = entry[name_index]

                pos = level_index
                field_is_enabled_in_guideline = {}
                while pos < len(entry):
                    level = entry[pos]
                    condition = entry[pos + level_to_condition_index]
                    guideline = entry[pos + level_to_guideline_index]

                    valid_condition = True
                    # Add an empty string to the notes so that all the notes are in the same position of their entry
                    notes.append("")
                    if isinstance(self, Generator):
                        enabled = level in ["MUST", "RECOMMENDED"]
                    else:
                        enabled = ConditionParser.is_enabled(self._user_configuration, sheet, name, entry,
                                                             certificate_index=self._certificate_index)
                    if condition:
                        tokens = re.split(self._condition_parser.splitting_capturing_regex, condition,
                                          flags=re.IGNORECASE)
                        tokens = [token for token in tokens if token]
                        # If a condition of type "this or" goes through it checks the user_configuration status which at
                        # this point is not filled yet
                        if isinstance(self, Generator):
                            while "THIS" in tokens:
                                i = tokens.index("THIS")
                                tokens.insert(i, "True")
                                i += 1
                                removing = 2
                                while i < len(tokens) and removing:
                                    if tokens[i] in [" and ", " or "]:
                                        removing -= 1
                                    if removing:
                                        tokens.pop(i)
                            condition = " ".join(tokens)

                        valid_condition = self._condition_parser.run(condition, enabled, cert_index=self._certificate_index)
                        enabled = self._condition_parser.entry_updates.get("is_enabled", enabled)
                        if self._condition_parser.entry_updates.get("disable_if"):
                            enabled = self.check_disable_if(self._condition_parser.entry_updates.get("disable_if"),
                                                            enabled, valid_condition)
                        self._logging.debug(f"Condition: {condition} - enabled: {enabled} - valid: {valid_condition}")
                        if self._condition_parser.entry_updates.get("flip_level"):
                            level = self.level_flipper.get(level, level)
                        if self._condition_parser.entry_updates.get("levels"):
                            potential_levels = self._condition_parser.entry_updates.get("levels")
                            level = potential_levels[self.level_to_use(potential_levels)]
                        has_alternative = self._condition_parser.entry_updates.get("has_alternative")
                        additional_notes = self._condition_parser.entry_updates.get("notes", "")
                        conditional_notes = self.add_conditional_notes(enabled, valid_condition)
                        notes[-1] += conditional_notes
                        if has_alternative and not enabled and isinstance(condition, str) and condition.count(" ") > 1:
                            parts = condition.split(" ")
                            # Tokens[1] is the logical operator
                            notes[-1] += f"\nNOTE: {name} {parts[1].upper()} {' '.join(parts[2:])} is needed"
                            # This is to trigger the output condition. This works because I'm assuming that "THIS"
                            # is only used in a positive (recommended, must) context.
                            valid_condition = True
                        if additional_notes:
                            notes[-1] += "\nNOTE:"
                            notes[-1] += "\n".join(additional_notes)

                    conditions.append(valid_condition)
                    levels.append(level)
                    field_is_enabled_in_guideline[guideline] = enabled
                    pos += step
                best_level = self.level_to_use(levels)
                resulting_level = levels[best_level]
                condition = conditions[best_level]
                note = notes[best_level]
                # if best level is 0 it is the first one
                source_guideline = entry[guideline_index + step * best_level]

                for guideline in custom_guidelines_list:
                    custom_entry = self._custom_guidelines[sheet][guideline].get(name)
                    if custom_entry:
                        levels = [resulting_level, custom_entry["level"]]
                        guidelines_to_check = list(sheets_to_check[sheet])
                        # If the custom_guideline appears before the source_guideline (actual guideline from which
                        # the level was deducted) it has greater priority, so it is necessary to switch them
                        if guidelines_to_check.index(guideline) < guidelines_to_check.index(source_guideline):
                            levels = levels[::-1]
                        best_level = self.level_to_use(levels)
                        # if best_level is 0 the source_guideline is the best
                        if best_level:
                            source_guideline = guideline
                        resulting_level = levels[best_level]

                # Custom guidelines don't have notes
                if source_guideline.upper() not in self._guidelines:
                    note = ""

                # Save it to the dictionary
                self.evaluated_entries[sheet][total] = {
                    "entry": entry,
                    "level": resulting_level,
                    "source": source_guideline,
                    "enabled": field_is_enabled_in_guideline[source_guideline],
                    "valid_condition": condition,
                    "note": note
                }
                total += 1

    @staticmethod
    def check_disable_if(condition, enabled, valid_condition):
        if not condition:
            return enabled
        if isinstance(condition, str):
            if condition in ["True", "False"]:
                return (condition == "True") == valid_condition
        return enabled


class Generator(Compliance):
    """This class only exists to add fields that are needed by the generator to the Compliance class"""

    def __init__(self):
        super().__init__()
        self._configuration_rules = load_configuration("configuration_rules", "configs/compliance/generate/")
        self._configuration_mapping = load_configuration("configuration_mapping", "configs/compliance/generate/")

    def _get_config_name(self, field):
        name = self._configuration_mapping.get(field, None)
        if isinstance(name, dict):
            name = list(name.keys())[0]
        return name

    def _fill_user_configuration(self):
        assert self._config_class is not None
        # reset user_configuration to avoid issues
        self._user_configuration = {}
        output_dict = self._config_class.output_dict
        for field in output_dict:
            config_field = self._get_config_name(field)
            save_in = self._user_configuration_types.get(config_field)
            save_in = self._type_converter.get(save_in)
            current_field = output_dict[field]
            if config_field and save_in:
                if self._user_configuration.get(config_field) is None:
                    self._user_configuration[config_field] = save_in()
                user_conf_field = self._user_configuration[config_field]
                if isinstance(user_conf_field, list):
                    values = [val for val in current_field if current_field[val]["added"]]
                    user_conf_field.extend(values)
                elif isinstance(user_conf_field, set):
                    values = [val for val in current_field if current_field[val]["added"]]
                    user_conf_field.update(values)
                elif isinstance(user_conf_field, dict):
                    for val in current_field:
                        if config_field == "Protocol":
                            new_val = val.replace("v", " ")
                            if len(new_val) < 6:
                                new_val += ".0"
                            user_conf_field[new_val] = current_field[val]["added"]
                        elif config_field == "Extension":
                            self._database_instance.input(["Extension"], other_filter=f'WHERE name=="{val}"')
                            iana_code = self._database_instance.output(["iana_code"])[0][0]
                            user_conf_field[str(iana_code)] = val

    # To override
    def _worker(self, sheets_to_check, hostname):
        """
        :param sheets_to_check: dict of sheets that should be checked in the form: sheet:{protocol, version_of_protocol}
        :type sheets_to_check: dict

        :return: processed results
        :rtype: dict

        :raise  NotImplementedError:
        """
        raise NotImplementedError("This method should be reimplemented")

    def _check_conditions(self):
        """
        Checks the conditions and removes/adds fields if needed
        """
        conditions_to_check = self._config_class.conditions_to_check
        for index in conditions_to_check:
            expression = conditions_to_check[index]["expression"]
            level = get_standardized_level(conditions_to_check[index]["level"])
            data = conditions_to_check[index]["data"]
            columns = conditions_to_check[index]["columns"]
            guideline = conditions_to_check[index]["guideline"]
            field = conditions_to_check[index]["field"]
            enabled = level in ["recommended", "must"]
            name = conditions_to_check[index]["name"]
            valid_condition = self._condition_parser.run(expression, enabled, cert_index=self._certificate_index)
            field_rules = self._configuration_rules.get(field, {})
            if self._condition_parser.entry_updates.get("levels"):
                potential_levels = self._condition_parser.entry_updates.get("levels")
                level = potential_levels[self.level_to_use(potential_levels)]
            if not valid_condition and enabled:
                self._config_class.remove_field(field, name)
            elif level in ["not recommended", "must not"] and valid_condition:
                self._config_class.remove_field(field, name)
            elif enabled and valid_condition:
                self._config_class.add_configuration_for_field(field, field_rules, data, columns, guideline)

    def output(self):
        self._fill_user_configuration()
        self._condition_parser = ConditionParser(self._user_configuration)
        self._check_conditions()
        return self._config_class.configuration_output()


class AliasParser:
    def __init__(self):
        self.__logging = Logger("Compliance module")
        self._database_instance = Database()
        self._guidelines = [name[0].upper() for name in self._database_instance.run(["Guideline"])]
        # simple regex to find and capture all occurrences of the guidelines
        self._splitting_regex = "(" + ")|(".join(self._guidelines) + ")"
        self._sheets_versions_dict = {}
        self._fill_sheets_dict()
        self._guidelines_versions = {}
        self._fill_guidelines_versions()
        self._aliases = load_configuration("alias_mapping", "configs/compliance/alias/")
        self._default_versions = load_configuration("default_versions", "configs/compliance/alias/")

    def list_aliases(self):
        print("Alias mapping:")
        for el in self._aliases:
            print(el, ":", self._aliases[el])
        import sys
        sys.exit(0)

    def list_strings(self):
        print("Valid strings:")
        for guideline in self._guidelines_versions:
            sets = [self._guidelines_versions[guideline][k] for k in self._guidelines_versions[guideline]]
            # this first list comprehension is needed to later check if there are any versions.
            combinations = [combination for combination in itertools.product(*sets)]
            if combinations and combinations[0]:
                print("Strings for guideline: ", guideline)
                # First I join the output from itertools.product using "-" then I prepend guideline_ to it and in the
                # end I join all the versions using ","
                result = ",".join([guideline + "-" + "-".join(combination) for combination in combinations])
                print(result)
            else:
                print("Guideline ", guideline, " doesn't have any special version")
            print("")
        print("NOTE: if a version is omitted the default one will be used.")
        import sys
        sys.exit(0)

    def _fill_sheets_dict(self):
        for table in self._database_instance.table_names:
            tokens = re.split(self._splitting_regex, table, flags=re.IGNORECASE)
            tokens = [t for t in tokens if t]
            # If the length is one or less the table is a general data table.
            if len(tokens) > 1:
                sheet = tokens[0]
                guideline = tokens[1]
                version = tokens[2] if len(tokens) == 3 else ""
                if self._sheets_versions_dict.get(sheet) is None:
                    self._sheets_versions_dict[sheet] = {guideline: set()}
                if self._sheets_versions_dict[sheet].get(guideline) is None:
                    self._sheets_versions_dict[sheet][guideline] = set()
                self._sheets_versions_dict[sheet][guideline].add(version)

    def _fill_guidelines_versions(self):
        for i, sheet in enumerate(self._sheets_versions_dict):
            for guideline in self._sheets_versions_dict[sheet]:
                if self._guidelines_versions.get(guideline) is None:
                    self._guidelines_versions[guideline] = {}
                guideline_dict = self._guidelines_versions[guideline]
                for version in self._sheets_versions_dict[sheet][guideline]:
                    new_set = True
                    for index in guideline_dict:
                        if version.upper() in guideline_dict[index]:
                            new_set = False
                    if new_set and version:
                        if guideline_dict.get(i) is None:
                            guideline_dict[i] = set()
                        guideline_dict[i].add(version.upper())

    def is_valid(self, alias):
        if "-" not in alias and alias.upper() not in self._guidelines:
            raise ValueError(f"Alias {alias} not valid")
        tokens = alias.split("-")
        guideline = tokens[0].upper()
        if guideline not in self._guidelines_versions:
            raise ValueError(f"Invalid guideline in alias: {alias}")
        used_sets = set()
        for token in tokens[1:]:
            found = False
            for index in self._guidelines_versions[guideline]:
                # If it is an abbreviation get the complete name.
                token = self._aliases.get(token.upper(), token.upper())
                if token in self._guidelines_versions[guideline][index] and index not in used_sets:
                    found = True
                    used_sets.add(index)
            if not found:
                raise ValueError(f"Invalid version {token} for alias: {alias}")

    def get_sheets_to_check(self, aliases):
        sheets_to_check = {}
        for alias in aliases:
            alias = alias.strip()
            if alias == "list":
                # print the list. The function terminates the program
                self.list_strings()
            if alias == "aliases":
                self.list_aliases()
            self.is_valid(alias)
            tokens = alias.split("-")
            guideline = tokens[0].upper()
            tokens.append("")
            for i, sheet in enumerate(self._sheets_versions_dict):
                if sheets_to_check.get(sheet) is None:
                    sheets_to_check[sheet] = {}
                for token in tokens[1:]:
                    token = token.upper()
                    # If it is an abbreviation get the complete name.
                    token = self._aliases.get(token, token)
                    if sheet + guideline + token in self._database_instance.table_names:
                        sheets_to_check[sheet][guideline] = token
                if sheets_to_check[sheet].get(guideline) is None:
                    version = self._default_versions[sheet].get(guideline)
                    if version is not None:
                        sheets_to_check[sheet][guideline] = version
                    else:
                        self.__logging.info(f"Skipping {guideline} in {sheet} because no version is available.")
        to_remove = set()
        for sheet in sheets_to_check.keys():
            if not sheets_to_check[sheet].keys():
                to_remove.add(sheet)
        for sheet in to_remove:
            del sheets_to_check[sheet]
        return sheets_to_check
