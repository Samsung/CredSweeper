import itertools
import json
import multiprocessing
import os
import sys
from typing import Dict, List, Optional

from credsweeper.common.constants import KeyValidationOption
from credsweeper.config import Config
from credsweeper.credentials import Candidate, CredentialManager
from credsweeper.logger.logger import logging
from credsweeper.scanner import Scanner
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.validations.apply_validation import ApplyValidation


class CredSweeper:
    """ Advanced credential analyzer base class

    Attributes:
        credential_manager: CredSweeper credential manager object
        scanner: CredSweeper scanner object
        POOL_COUNT: number of pools used to run multiprocessing scanning
        config: dictionary variable, stores analyzer features
        json_filename: string variable, credential candidates export filename
    """
    def __init__(self,
                 rule_path: Optional[str] = None,
                 ml_validation: bool = False,
                 api_validation: bool = False,
                 json_filename: Optional[str] = None,
                 use_filters: bool = True,
                 pool_count: Optional[int] = None,
                 ml_batch_size: Optional[int] = 16) -> None:
        """Initialize Advanced credential scanner

        Args:
            rule_path: optional str variable, path of rule config file
            ml_validation: optional boolean variable, specifying the need for
                validation was the grained candidate model on machine learning
            api_validation: optional boolean variable, specifying the need of
                parallel API validation
            json_filename: optional string variable, path to save result
                to json
            use_filters: boolean variable, specifying the need of rule filters
            pool_count: int value, number of parallel processes to use
            ml_batch_size: int value, size of the batch for model inference
        """
        if pool_count is None:
            pool_count = self.__get_pool_count()
        self.pool_count: int = pool_count
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(os.path.join(dir_path, "secret", "config.json"), "r") as conf_file:
            config_dict = json.load(conf_file)

        config_dict["validation"] = {}
        config_dict["validation"]["ml_validation"] = ml_validation
        config_dict["validation"]["api_validation"] = api_validation
        config_dict["use_filters"] = use_filters
        self.config = Config(config_dict)
        self.credential_manager = CredentialManager()
        self.scanner = Scanner(self.config, rule_path)
        self.json_filename: Optional[str] = json_filename
        self.ml_batch_size = ml_batch_size

    def __get_pool_count(self) -> int:
        """Get the number of pools based on doubled CPUs in the system"""
        if self.__is_pytest_running():
            return 1
        return os.cpu_count() * 2

    def __is_pytest_running(self) -> bool:
        """Check for running the module as part of testing"""
        return "pytest_cov" in sys.modules

    @property
    def config(self) -> Dict:
        return self.__config

    @config.setter
    def config(self, config: Dict) -> None:
        self.__config = config

    def run(self, content_provider: List[ContentProvider]) -> None:
        """Run an analysis directories paths

        Args:
            content_provider: list of path object to scan
        """
        file_extractors = []
        if content_provider:
            file_extractors = content_provider.get_scannable_files(self.config)
        logging.info("Start Scanner")
        self.scan(file_extractors)
        self.post_processing()
        self.export_results()

    def scan(self, file_providers: List[ContentProvider]) -> None:
        """Run scanning of files from an argument "file_providers"

        Args:
            file_providers: list of ContentProvider, file objects to scan
        """
        with multiprocessing.get_context("spawn").Pool(self.pool_count) as pool:
            # Get list credentials for each file
            scan_results_per_file = pool.map(self.file_scan, file_providers)
            # Join all sublist into a single list
            scan_results = list(itertools.chain(*scan_results_per_file))
            for cred in scan_results:
                self.credential_manager.add_credential(cred)
            if self.config.api_validation:
                logging.info("Run API Validation")
                api_validation = ApplyValidation()
                api_validation.validate_credentials(pool, self.credential_manager)

    def file_scan(self, file_provider: ContentProvider) -> List[Candidate]:
        """Run scanning of file from 'file_provider'

        Args:
            file_provider: file provider object to scan

        Return:
            list of credential candidates from scanned file
        """
        # Get list credentials for each file
        logging.debug(f"Start scan file: {file_provider.file_path}")
        try:
            scanContext = file_provider.get_analysis_target()
            return self.scanner.scan(scanContext)
        except UnicodeDecodeError:
            logging.warning(f"Can't read file content from \"{file_provider.file_path}\".")
            return []

    def post_processing(self) -> None:
        """Machine learning validation for received credential candidates"""
        if self.config.ml_validation:
            from credsweeper.ml_model import MlValidator
            MlValidator()
            logging.info("Run ML Validation")
            new_cred_list = []
            cred_groups = self.credential_manager.group_credentials()
            ml_cred_groups = []
            for group_key, group_candidates in cred_groups.items():
                # Analyze with ML if all candidates in group require ML
                if all(candidate.use_ml for candidate in group_candidates):
                    ml_cred_groups.append((group_key.value, group_candidates))
                # If at least one of credentials in the group do not require ML - automatically report to user
                else:
                    for candidate in group_candidates:
                        candidate.ml_validation = KeyValidationOption.NOT_AVAILABLE
                    new_cred_list += group_candidates

            pred = MlValidator.validate_groups(ml_cred_groups, self.ml_batch_size)
            for i, (_, group_candidates) in enumerate(ml_cred_groups):
                if pred[i]:
                    for candidate in group_candidates:
                        candidate.ml_validation = KeyValidationOption.VALIDATED_KEY
                    new_cred_list += group_candidates

            self.credential_manager.set_credentials(new_cred_list)

    def export_results(self) -> None:
        """Save credential candidates to json file"""
        for credential in self.credential_manager.get_credentials():
            print(credential)

        if self.json_filename:
            with open(self.json_filename, "w") as result_file:
                json.dump([credential.to_json() for credential in self.credential_manager.get_credentials()],
                          result_file,
                          indent=4)
