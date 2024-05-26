import logging
from pathlib import Path
import os

from utils.logger import Logger
from utils.validation import Validator  
from utils.loader import load_module

#from SEBASTiAn.main import perform_analysis_with_timeout # this line is commented out because the wrapper is used instead of calling SEBASTIAN's method
from typing import List
from dependencies.SEBASTiAn.src.SEBASTiAn.analysis import AndroidAnalysis
from dependencies.SEBASTiAn.src.SEBASTiAn.vulnerability import VulnerabilityDetails
from dependencies.SEBASTiAn.src.SEBASTiAn.manager import AndroidVulnerabilityManager

class Sebastian:
    """
    SEBESTiAn is a tool to perform static analysis of Android applications.
    """ 

    __cache = {}
    __instance = None

    def __init__(self) -> None:
        loggers_to_set = [
            "AllowAllHostname",
            "CryptoEcbCipher",
            "DebuggableApplication",
            "DefaultSchemeHttp",
            "InsecureConnection",
            "InsecureHostnameVerifier",
            "InsecureSocket",
            "InsecureSocketFactory",
            "InvalidServerCertificate",
            "SEBASTiAn"
        ]
        for logger_name in loggers_to_set:
            logger = logging.getLogger(logger_name)
            logger.setLevel(
                logging.CRITICAL if not logger.isEnabledFor(logging.DEBUG) else logging.DEBUG
            )

        self.__logging = Logger("sebastian")
        self.__sebastian = f"dependencies{os.sep}SEBASTiAn{os.sep}src{os.sep}SEBASTiAn{os.sep}main.py"
        self.__instance = load_module(self.__sebastian, "sebastian")
        self.__input_dict = {}
        self.__correct_path = None

    def input(self, **kwargs):
        """
        This method is used to set the input

        :param kwargs:
        :Keyword Arguments:
            path: path to the file to be analyzed
            args: list of arguments to be passed to mallodroid
            force: force the analysis of the file (default: False)
        """
        self.__input_dict = kwargs

    def output(self, **kwargs) -> dict:
        """
        This method is used to get the output of the analysis

        :param kwargs:
        :Keyword Arguments:
            path: path to the file to be analyzed

        :return: a dictionary result
        :rtype: dict
        """
        return (
            self.__cache[kwargs["path"]]
            if "path" in kwargs and kwargs["path"] in self.__cache
            else {}
        )

    def run(self, **kwargs) -> dict:
        """
        This method is used to run the analysis

        :param kwargs:
        :Keyword Arguments:
            path: path to the file to be analyzed
            args: list of arguments to be passed to mallodroid
            force: force the analysis of the file ignoring cache (default: False)
        """
        self.input(**kwargs)
        if "path" in self.__input_dict:
            self.__correct_path = Path(self.__input_dict["path"])
            if not self.__correct_path.exists():
                raise FileNotFoundError(
                    f"Couldn't find the file {self.__correct_path}."
                )
        else:
            raise AssertionError("Path argument missing.")
        # validate input types
        args = self.__input_dict["args"] if "args" in self.__input_dict else []
        force = self.__input_dict["force"] if "force" in self.__input_dict else False
        Validator([(args, list), (force, bool)])
        self.__worker(self.__correct_path, args=args, force=force)
        return self.output(path=str(self.__correct_path.absolute()))

    def __worker(self, path: Path, args: list, force: bool):
        """
        This method is the worker method to be executed by run()

        :param path: path to the file to be analyzed
        :param args: list of arguments to be passed to mallodroid
        :param force: force the analysis of the file ignoring cache (default: False)

        """
        file_id = str(path.absolute())
        self.__logging.debug(f"Starting analysis of {file_id} ...")
          
        if force:
            self.__logging.debug(
                f"Analysis of {file_id} (cache miss or forced by call)"
            )
            try:
                self.__cache[file_id] = self.perform_analysis_without_timeout(file_id,plugins=["AllowAllHostname","CryptoEcbCipher","DebuggableApplication","DefaultSchemeHttp","InsecureConnection","InsecureHostnameVerifier","InsecureSocket","InsecureSocketFactory","InvalidServerCertificate"])
            except Exception as e:
                self.__logging.error(f"Analysis of {file_id} crashed: {e}")
        else:
            if file_id not in self.__cache:  # if not in cache, force analysis
                self.__worker(path, args, force=True)


    ############################################
    #         Wrapper of SEBASTiAn            #
    ############################################
    def perform_analysis_without_timeout(
        self,
        input_app_path: str,
        language: str = "en",
        ignore_libs: bool = False,
        fail_fast: bool = False,
        keep_files: bool = False,
        generate_report: bool = False,
        plugins: List[str] = None,  
    ) -> dict:
        """
        This method wrap the method perform_analysis_without_timeout of SEBASTiAn, allowing you to choose which plugin to analyze
        """
        analysis = None
        found_vulnerabilities: List[VulnerabilityDetails] = []
        failures = 0
        platform="Android"
        try:
            manager = AndroidVulnerabilityManager()
            analysis = AndroidAnalysis(
                input_app_path, language, ignore_libs, generate_report
            )
            analysis.initialize()

            # Get the list of all available plugins
            all_plugins = [item.plugin_object.__class__.__name__ for item in manager.get_all_vulnerability_checks()]
            if plugins:
                # Verify if the specified plugins exist
                non_existing_plugins = [plugin for plugin in plugins if plugin not in all_plugins]
                if non_existing_plugins:
                    self.__logging.error(f"The following specified plugins do not exist: {', '.join(non_existing_plugins)}")
                # Filter the vulnerability checks to include only the specified plugins
                filtered_checks = [item for item in manager.get_all_vulnerability_checks() if item.plugin_object.__class__.__name__ in plugins]
            else:
                filtered_checks = manager.get_all_vulnerability_checks()
            for item in filtered_checks:
                try:
                    vulnerability_details = item.plugin_object.check_vulnerability(analysis)
                    if vulnerability_details:
                        found_vulnerabilities.append(vulnerability_details)
                except Exception:
                    failures += 1
                    if fail_fast:
                        # Make the entire vulnerability analysis fail only if the
                        # corresponding flag is enabled.
                        raise
                    
        except Exception as e:
            self.__logging.error(f"Vulnerability analysis failed: {e}")
            raise

        else:
            result = {
                "vulnerabilities": VulnerabilityDetails.Schema().dump(found_vulnerabilities, many=True)
            }
            return result