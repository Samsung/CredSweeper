import threading
import time
from typing import List, Optional, Union, Dict
import itertools
import json
import os
import signal
import sys
import regex

from credsweeper.common.constants import KeyValidationOption, ThresholdPreset, DEFAULT_ENCODING, Severity
from credsweeper.config import Config
from credsweeper.credentials import Candidate, CredentialManager, LineData
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.file_handler.diff_content_provider import DiffContentProvider
from credsweeper.file_handler.text_content_provider import TextContentProvider
from credsweeper.file_handler.file_path_extractor import FilePathExtractor
from credsweeper.file_handler.files_provider import FilesProvider
from credsweeper.logger.logger import logging
from credsweeper.ml_model import MlValidator
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
        self.ml_validator = MlValidator(threshold=self.ml_threshold)

    def _use_ml_validation(self) -> bool:
        if isinstance(self.ml_threshold, float) and self.ml_threshold <= 0:
            return False
        return True

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
        file_extractors = content_provider.get_scannable_files(self.config) if content_provider else []
        logging.info("Start Scanner")
        self.scan(file_extractors)
        if self._use_ml_validation():
            self.post_processing()
        self.export_results()

    def scan(self, content_providers: Union[List[DiffContentProvider], List[TextContentProvider]]) -> None:
        """Run scanning of files from an argument "file_providers".

        Args:
            content_providers: file objects to scan

        """
        if 1 < self.pool_count:
            __thread_data: Dict[Union[DiffContentProvider, TextContentProvider], Union[None, List[Candidate]]] = dict()
            for i in content_providers:
                __thread_data[i] = None
            _repeat = True
            __threads_active = []
            for key, val in __thread_data.items():
                while self.pool_count <= len(__threads_active):
                    time.sleep(0)
                    __threads_done = []
                    for i in __threads_active:
                        if not i.is_alive():
                            i.join()
                            __threads_done.append(i)
                    for i in __threads_done:
                        __threads_active.remove(i)
                if val is None:
                    t = threading.Thread(target=self.__threading_file_scan, args=(key, __thread_data))
                    __threads_active.append(t)
                    t.start()
            while 0 < len(__threads_active):
                time.sleep(0)
                __threads_done = []
                for i in __threads_active:
                    if not i.is_alive():
                        i.join()
                        __threads_done.append(i)
                for i in __threads_done:
                    __threads_active.remove(i)
            for key, val in __thread_data.items():
                self.credential_manager.extend_credentials(val)

        else:
            all_cred: List[Candidate] = []
            for i in content_providers:
                all_cred.extend(self.file_scan(i))
            for cred in all_cred:
                if self.config.api_validation:
                    logging.info("Run API Validation")
                    api_validation = ApplyValidation()
                    cred.api_validation = api_validation.validate(cred)
                self.credential_manager.add_credential(cred)

    def __threading_file_scan(self, content_provider: Union[DiffContentProvider, TextContentProvider],
                              data: Dict[
                                  Union[DiffContentProvider, TextContentProvider], Union[
                                      None, List[Candidate]]]) -> None:
        """Thread duty"""
        data[content_provider] = []
        for cred in self.file_scan(content_provider):
            if self.config.api_validation:
                logging.info("Run API Validation")
                api_validation = ApplyValidation()
                cred.api_validation = api_validation.validate(cred)
            data[content_provider].append(cred)

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
