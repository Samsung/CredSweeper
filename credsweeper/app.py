import itertools
import json
import multiprocessing
import os
import signal
import sys
from typing import Dict, List, Optional, Tuple

import regex

from credsweeper.common.constants import KeyValidationOption, ThresholdPreset, DEFAULT_ENCODING, Severity
from credsweeper.config import Config
from credsweeper.credentials import Candidate, CredentialManager, LineData
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.file_handler.file_path_extractor import FilePathExtractor
from credsweeper.logger.logger import logging
from credsweeper.scanner import Scanner
from credsweeper.validations.apply_validation import ApplyValidation


class CredSweeper:
    """Advanced credential analyzer base class.

    Parameters:
        credential_manager: CredSweeper credential manager object
        scanner: CredSweeper scanner object
        pool_count: number of pools used to run multiprocessing scanning
        config: dictionary variable, stores analyzer features
        json_filename: string variable, credential candidates export filename

    """

    def __init__(self,
                 rule_path: Optional[str] = None,
                 ml_validation: bool = False,
                 api_validation: bool = False,
                 json_filename: Optional[str] = None,
                 use_filters: bool = True,
                 pool_count: int = 1,
                 ml_batch_size: Optional[int] = 16,
                 ml_threshold: Optional[Tuple[float, ThresholdPreset]] = None,
                 find_by_ext: bool = False) -> None:
        """Initialize Advanced credential scanner.

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
            ml_threshold: float or string value to specify threshold for the ml model

        """
        self.pool_count: int = pool_count if pool_count > 1 else 1
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(os.path.join(dir_path, "secret", "config.json"), "r", encoding=DEFAULT_ENCODING) as conf_file:
            config_dict = json.load(conf_file)

        config_dict["validation"] = {}
        config_dict["validation"]["ml_validation"] = ml_validation
        config_dict["validation"]["api_validation"] = api_validation
        config_dict["use_filters"] = use_filters
        config_dict["find_by_ext"] = find_by_ext

        self.ml_validator: Optional = None
        self.config = Config(config_dict)
        self.credential_manager = CredentialManager()
        self.scanner = Scanner(self.config, rule_path)
        self.json_filename: Optional[str] = json_filename
        self.ml_batch_size = ml_batch_size
        self.ml_threshold = ml_threshold
        self.find_by_ext = find_by_ext

    def pool_initializer(self) -> None:
        """Ignore SIGINT in child processes."""
        signal.signal(signal.SIGINT, signal.SIG_IGN)

    @property
    def config(self) -> Dict:
        return self.__config

    @config.setter
    def config(self, config: Dict) -> None:
        self.__config = config

    def run(self, content_provider: List[ContentProvider]) -> None:
        """Run an analysis of 'content_provider' object.

        Args:
            content_provider: path objects to scan

        """
        file_extractors = []
        if content_provider:
            file_extractors = content_provider.get_scannable_files(self.config)
        logging.info("Start Scanner")
        self.scan(file_extractors)
        self.post_processing()
        self.export_results()

    def scan(self, file_providers: List[ContentProvider]) -> None:
        """Run scanning of files from an argument "file_providers".

        Args:
            file_providers: file objects to scan

        """
        with multiprocessing.get_context("spawn").Pool(self.pool_count, initializer=self.pool_initializer) as pool:
            try:
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
            except KeyboardInterrupt:
                pool.terminate()
                pool.join()
                sys.exit()

    def file_scan(self, file_provider: ContentProvider) -> List[Candidate]:
        """Run scanning of file from 'file_provider'.

        Args:
            file_provider: file provider object to scan

        Return:
            list of credential candidates from scanned file

        """
        # Get list credentials for each file
        logging.debug(f"Start scan file: {file_provider.file_path}")

        if self.config.find_by_ext:
            if FilePathExtractor.is_find_by_ext_file(self.config, file_provider.file_path):
                candidate = Candidate(line_data_list=[
                    LineData(self.config,
                             line="dummy line",
                             line_num=-1,
                             path=file_provider.file_path,
                             pattern=regex.compile(".*"))
                ],
                                      patterns=[regex.compile(".*")],
                                      rule_name="Dummy candidate",
                                      severity=Severity.INFO,
                                      config=self.config)
                return [candidate]

        try:
            scan_context = file_provider.get_analysis_target()
            return self.scanner.scan(scan_context)
        except UnicodeDecodeError:
            logging.warning(f"Can't read file content from \"{file_provider.file_path}\".")
            return []

    def post_processing(self) -> None:
        """Machine learning validation for received credential candidates."""
        if self.config.ml_validation:
            if self.ml_validator is None:
                from credsweeper.ml_model import MlValidator
                self.ml_validator = MlValidator(threshold=self.ml_threshold)
            assert self.ml_validator
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

            is_cred, probability = self.ml_validator.validate_groups(ml_cred_groups, self.ml_batch_size)
            for i, (_, group_candidates) in enumerate(ml_cred_groups):
                if is_cred[i]:
                    for candidate in group_candidates:
                        candidate.ml_validation = KeyValidationOption.VALIDATED_KEY
                        candidate.ml_probability = probability[i]
                    new_cred_list += group_candidates

            self.credential_manager.set_credentials(new_cred_list)

    def export_results(self) -> None:
        """Save credential candidates to json file or print them to a console."""
        if self.json_filename:
            with open(self.json_filename, "w", encoding=DEFAULT_ENCODING) as result_file:
                json.dump([credential.to_json() for credential in self.credential_manager.get_credentials()],
                          result_file,
                          indent=4)
        else:
            for credential in self.credential_manager.get_credentials():
                print(credential)
