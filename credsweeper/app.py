from typing import List, Optional, Union, Any
import itertools
import json
import multiprocessing
import os
import signal
import sys
import regex

from credsweeper.common.constants import KeyValidationOption, ThresholdPreset, DEFAULT_ENCODING, Severity
from credsweeper.config import Config
from credsweeper.credentials import Candidate, CredentialManager, LineData
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.file_handler.file_path_extractor import FilePathExtractor
from credsweeper.file_handler.files_provider import FilesProvider
from credsweeper.file_handler.diff_content_provider import DiffContentProvider
from credsweeper.file_handler.text_content_provider import TextContentProvider
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
                 api_validation: bool = False,
                 json_filename: Optional[str] = None,
                 use_filters: bool = True,
                 pool_count: int = 1,
                 ml_batch_size: Optional[int] = 16,
                 ml_threshold: Union[float, ThresholdPreset] = ThresholdPreset.medium,
                 find_by_ext: bool = False,
                 size_limit: Optional[str] = None) -> None:
        """Initialize Advanced credential scanner.

        Args:
            rule_path: optional str variable, path of rule config file
                validation was the grained candidate model on machine learning
            api_validation: optional boolean variable, specifying the need of
                parallel API validation
            json_filename: optional string variable, path to save result
                to json
            use_filters: boolean variable, specifying the need of rule filters
            pool_count: int value, number of parallel processes to use
            ml_batch_size: int value, size of the batch for model inference
            ml_threshold: float or string value to specify threshold for the ml model
            find_by_ext: boolean - files will be reported by extension
            size_limit: optional string integer or human-readable format to skip oversize files

        """
        self.pool_count: int = int(pool_count) if int(pool_count) > 1 else 1
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(os.path.join(dir_path, "secret", "config.json"), "r", encoding=DEFAULT_ENCODING) as conf_file:
            config_dict = json.load(conf_file)

        config_dict["validation"] = {}
        config_dict["validation"]["api_validation"] = api_validation
        config_dict["use_filters"] = use_filters
        config_dict["find_by_ext"] = find_by_ext
        config_dict["size_limit"] = size_limit

        self.config = Config(config_dict)
        self.credential_manager = CredentialManager()
        self.scanner = Scanner(self.config, rule_path)
        self.json_filename: Optional[str] = json_filename
        self.ml_batch_size = ml_batch_size
        self.ml_threshold = ml_threshold
        # the import cannot be done on top due
        # TypeError: cannot pickle 'onnxruntime.capi.onnxruntime_pybind11_state.InferenceSession' object
        from credsweeper.ml_model import MlValidator
        self.__ml_validator: Any[MlValidator] = None

    def _use_ml_validation(self) -> bool:
        if isinstance(self.ml_threshold, float) and self.ml_threshold <= 0:
            return False
        return True

    from credsweeper.ml_model import MlValidator

    @property
    def ml_validator(self) -> MlValidator:
        """ml_validator getter"""
        from credsweeper.ml_model import MlValidator
        if self.__ml_validator is None:
            self.__ml_validator = MlValidator(threshold=self.ml_threshold)
        assert self.__ml_validator and isinstance(self.__ml_validator, MlValidator), \
            f"self.__ml_validator was not initialized or wrong instance '{self.__ml_validator.__class__}'"
        return self.__ml_validator

    @classmethod
    def pool_initializer(cls) -> None:
        """Ignore SIGINT in child processes."""
        signal.signal(signal.SIGINT, signal.SIG_IGN)

    @property
    def config(self) -> Config:
        """config getter"""
        return self.__config

    @config.setter
    def config(self, config: Config) -> None:
        """config setter"""
        self.__config = config

    def run(self, content_provider: FilesProvider) -> None:
        """Run an analysis of 'content_provider' object.

        Args:
            content_provider: path objects to scan

        """
        _empty_list_mypy_fix: List[TextContentProvider] = []
        file_extractors: Union[List[DiffContentProvider], List[TextContentProvider]] = \
            content_provider.get_scannable_files(self.config) if content_provider else _empty_list_mypy_fix
        logging.info("Start Scanner")
        self.scan(file_extractors)
        self.post_processing()
        self.export_results()

    def scan(self, content_providers: Union[List[DiffContentProvider], List[TextContentProvider]]) -> None:
        """Run scanning of files from an argument "content_providers".

        Args:
            content_providers: file objects to scan

        """
        if 1 < self.pool_count:
            self.__multi_jobs_scan(content_providers)
        else:
            self.__single_job_scan(content_providers)

    def __single_job_scan(self, content_providers: Union[List[DiffContentProvider], List[TextContentProvider]]):
        """Performs scan in main thread"""
        all_cred: List[Candidate] = []
        for i in content_providers:
            candidates = self.file_scan(i)
            all_cred.extend(candidates)
        if self.config.api_validation:
            api_validation = ApplyValidation()
            for cred in all_cred:
                logging.info("Run API Validation")
                cred.api_validation = api_validation.validate(cred)
                self.credential_manager.add_credential(cred)
        else:
            self.credential_manager.set_credentials(all_cred)

    def __multi_jobs_scan(self, content_providers: Union[List[DiffContentProvider], List[TextContentProvider]]):
        """Performs scan with multiple jobs"""
        with multiprocessing.get_context("spawn").Pool(self.pool_count, initializer=self.pool_initializer) as pool:
            try:
                # Get list credentials for each file
                scan_results_per_file = pool.map(self.file_scan, content_providers)
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
                candidate = Candidate(
                    line_data_list=[
                        LineData(  #
                            self.config,  #
                            line="dummy line",  #
                            line_num=-1,  #
                            path=file_provider.file_path,  #
                            pattern=regex.compile(".*"))
                    ],
                    patterns=[regex.compile(".*")],  #
                    rule_name="Dummy candidate",  #
                    severity=Severity.INFO,  #
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
        if self._use_ml_validation():
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
