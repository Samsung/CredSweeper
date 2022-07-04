import json
import os
import threading
import time
from typing import List, Optional, Union, Dict

import regex

from credsweeper.common.constants import KeyValidationOption, ThresholdPreset, DEFAULT_ENCODING, Severity
from credsweeper.config import Config
from credsweeper.credentials import Candidate, CredentialManager, LineData
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.file_handler.diff_content_provider import DiffContentProvider
from credsweeper.file_handler.file_path_extractor import FilePathExtractor
from credsweeper.file_handler.files_provider import FilesProvider
from credsweeper.file_handler.text_content_provider import TextContentProvider
from credsweeper.logger.logger import logging
from credsweeper.ml_model import MlValidator
from credsweeper.scanner import Scanner
from credsweeper.validations.apply_validation import ApplyValidation


class CredSweeper:
    """Advanced credential analyzer base class."""

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
            pool_count: int value, number of threads to use in scan()
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
        self.ml_validator = MlValidator(threshold=self.ml_threshold)

    def _use_ml_validation(self) -> bool:
        if isinstance(self.ml_threshold, float) and self.ml_threshold <= 0:
            return False
        return True

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
        if self._use_ml_validation():
            self.post_processing()
        self.export_results()

    def scan(self, content_providers: Union[List[DiffContentProvider], List[TextContentProvider]]) -> None:
        """Run scanning of files from an argument "file_providers".

        Args:
            content_providers: file objects to scan

        """
        if 1 < self.pool_count:
            self.__threading_scan(content_providers)
        else:
            # one thread flow
            all_cred: List[Candidate] = []
            for i in content_providers:
                all_cred.extend(self.file_scan(i))
            for cred in all_cred:
                if self.config.api_validation:
                    logging.info("Run API Validation")
                    api_validation = ApplyValidation()
                    cred.api_validation = api_validation.validate(cred)
                self.credential_manager.add_credential(cred)

    def __threading_scan(self, content_providers: Union[List[DiffContentProvider], List[TextContentProvider]]) -> None:
        """Separated method to launch scan process in threads"""
        __thread_data: Dict[Union[DiffContentProvider, TextContentProvider], Union[None, List[Candidate]]] = dict()
        for i in content_providers:
            __thread_data[i] = None
        __threads_active: List[threading.Thread] = []
        for key, val in __thread_data.items():
            while self.pool_count <= len(__threads_active):
                time.sleep(0)
                __threads_done: List[threading.Thread] = []
                for t in __threads_active:
                    if not t.is_alive():
                        t.join()
                        __threads_done.append(t)
                for d in __threads_done:
                    __threads_active.remove(d)
            if val is None:
                t = threading.Thread(target=self.__threading_scan_func, args=(key, __thread_data))
                __threads_active.append(t)
                t.start()
        while 0 < len(__threads_active):
            time.sleep(0)
            __threads_final: List[threading.Thread] = []
            for _t_f in __threads_active:
                if not _t_f.is_alive():
                    _t_f.join()
                    __threads_final.append(_t_f)
            for _d_f in __threads_final:
                __threads_active.remove(_d_f)
        for key, val in __thread_data.items():
            self.credential_manager.extend_credentials(val)

    def __threading_scan_func(  #
            self,  #
            content_provider: Union[DiffContentProvider, TextContentProvider],  #
            thread_data: Dict[Union[DiffContentProvider, TextContentProvider], Union[None, List[Candidate]]]  #
    ) -> None:
        """Thread function

        Args:
            content_provider: an index in thread_data and data provider
            thread_data: returned results, each thread works with uniq element

        """
        thread_data[content_provider] = []
        for cred in self.file_scan(content_provider):
            if self.config.api_validation:
                logging.info("Run API Validation")
                api_validation = ApplyValidation()
                cred.api_validation = api_validation.validate(cred)
            thread_data[content_provider].append(cred)

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
        """Post processing"""
        if self._use_ml_validation():
            self.__ml_validate()

    def __ml_validate(self) -> None:
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
