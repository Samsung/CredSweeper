import gzip
import io
import itertools
import logging
import multiprocessing
import os
import signal
import sys
import zipfile
from typing import List, Optional, Union

import pandas as pd

from credsweeper.common.constants import KeyValidationOption, ThresholdPreset, RECURSIVE_SCAN_LIMITATION
from credsweeper.config import Config
from credsweeper.credentials import Candidate, CredentialManager
from credsweeper.file_handler.byte_content_provider import ByteContentProvider
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.diff_content_provider import DiffContentProvider
from credsweeper.file_handler.file_path_extractor import FilePathExtractor
from credsweeper.file_handler.files_provider import FilesProvider
from credsweeper.file_handler.text_content_provider import TextContentProvider
from credsweeper.scanner import Scanner
from credsweeper.utils import Util
from credsweeper.validations.apply_validation import ApplyValidation

logger = logging.getLogger(__name__)


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
                 config_path: Optional[str] = None,
                 api_validation: bool = False,
                 json_filename: Optional[str] = None,
                 xlsx_filename: Optional[str] = None,
                 use_filters: bool = True,
                 pool_count: int = 1,
                 ml_batch_size: Optional[int] = 16,
                 ml_threshold: Union[float, ThresholdPreset] = ThresholdPreset.medium,
                 find_by_ext: bool = False,
                 depth: int = 0,
                 size_limit: Optional[str] = None,
                 exclude_lines: Optional[List[str]] = None,
                 exclude_values: Optional[List[str]] = None) -> None:
        """Initialize Advanced credential scanner.

        Args:
            rule_path: optional str variable, path of rule config file
                validation was the grained candidate model on machine learning
            config_path: optional str variable, path of CredSweeper config file
                default built-in config is used if None
            api_validation: optional boolean variable, specifying the need of
                parallel API validation
            json_filename: optional string variable, path to save result
                to json
            xlsx_filename: optional string variable, path to save result
                to xlsx
            use_filters: boolean variable, specifying the need of rule filters
            pool_count: int value, number of parallel processes to use
            ml_batch_size: int value, size of the batch for model inference
            ml_threshold: float or string value to specify threshold for the ml model
            find_by_ext: boolean - files will be reported by extension
            depth: int - how deep container files will be scanned
            size_limit: optional string integer or human-readable format to skip oversize files
            exclude_lines: lines to omit in scan. Will be added to the lines already in config
            exclude_values: values to omit in scan. Will be added to the values already in config

        """
        self.pool_count: int = int(pool_count) if int(pool_count) > 1 else 1
        if config_path:
            config_dict = Util.json_load(config_path)
        else:
            dir_path = os.path.dirname(os.path.realpath(__file__))
            config_dict = Util.json_load(os.path.join(dir_path, "secret", "config.json"))

        config_dict["validation"] = {}
        config_dict["validation"]["api_validation"] = api_validation
        config_dict["use_filters"] = use_filters
        config_dict["find_by_ext"] = find_by_ext
        config_dict["size_limit"] = size_limit
        config_dict["depth"] = depth
        if exclude_lines is not None:
            config_dict["exclude"]["lines"] = config_dict["exclude"].get("lines", []) + exclude_lines
        if exclude_values is not None:
            config_dict["exclude"]["values"] = config_dict["exclude"].get("values", []) + exclude_values

        self.config = Config(config_dict)
        self.credential_manager = CredentialManager()
        self.scanner = Scanner(self.config, rule_path)
        self.json_filename: Optional[str] = json_filename
        self.xlsx_filename: Optional[str] = xlsx_filename
        self.ml_batch_size = ml_batch_size
        self.ml_threshold = ml_threshold
        self.ml_validator = None

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def _use_ml_validation(self) -> bool:
        if isinstance(self.ml_threshold, float) and self.ml_threshold <= 0:
            return False
        return True

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # the import cannot be done on top due
    # TypeError: cannot pickle 'onnxruntime.capi.onnxruntime_pybind11_state.InferenceSession' object
    from credsweeper.ml_model import MlValidator

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @property
    def ml_validator(self) -> MlValidator:
        """ml_validator getter"""
        from credsweeper.ml_model import MlValidator
        if not self.__ml_validator:
            self.__ml_validator: MlValidator = MlValidator(threshold=self.ml_threshold)
        assert self.__ml_validator, "self.__ml_validator was not initialized"
        return self.__ml_validator

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @ml_validator.setter
    def ml_validator(self, _ml_validator: Optional[MlValidator]) -> None:
        """ml_validator setter"""
        self.__ml_validator = _ml_validator

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @classmethod
    def pool_initializer(cls) -> None:
        """Ignore SIGINT in child processes."""
        signal.signal(signal.SIGINT, signal.SIG_IGN)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @property
    def config(self) -> Config:
        """config getter"""
        return self.__config

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @config.setter
    def config(self, config: Config) -> None:
        """config setter"""
        self.__config = config

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def run(self, content_provider: FilesProvider) -> int:
        """Run an analysis of 'content_provider' object.

        Args:
            content_provider: path objects to scan

        """
        _empty_list: List[TextContentProvider] = []
        file_extractors: Union[List[DiffContentProvider], List[TextContentProvider]] = \
            content_provider.get_scannable_files(self.config) if content_provider else _empty_list
        logger.info("Start Scanner")
        self.scan(file_extractors)
        self.post_processing()
        self.export_results()

        return len(self.credential_manager.get_credentials())

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def scan(self, content_providers: Union[List[DiffContentProvider], List[TextContentProvider]]) -> None:
        """Run scanning of files from an argument "content_providers".

        Args:
            content_providers: file objects to scan

        """
        if 1 < self.pool_count:
            self.__multi_jobs_scan(content_providers)
        else:
            self.__single_job_scan(content_providers)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def __single_job_scan(self, content_providers: Union[List[DiffContentProvider], List[TextContentProvider]]) -> None:
        """Performs scan in main thread"""
        all_cred: List[Candidate] = []
        for i in content_providers:
            candidates = self.file_scan(i)
            all_cred.extend(candidates)
        if self.config.api_validation:
            api_validation = ApplyValidation()
            for cred in all_cred:
                logger.info("Run API Validation")
                cred.api_validation = api_validation.validate(cred)
                self.credential_manager.add_credential(cred)
        else:
            self.credential_manager.set_credentials(all_cred)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def __multi_jobs_scan(self, content_providers: Union[List[DiffContentProvider], List[TextContentProvider]]) -> None:
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
                    logger.info("Run API Validation")
                    api_validation = ApplyValidation()
                    api_validation.validate_credentials(pool, self.credential_manager)
            except KeyboardInterrupt:
                pool.terminate()
                pool.join()
                sys.exit()

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def file_scan(self, content_provider: ContentProvider) -> List[Candidate]:
        """Run scanning of file from 'file_provider'.

        Args:
            content_provider: content provider object to scan

        Return:
            list of credential candidates from scanned file

        """
        candidates: List[Candidate] = []
        logger.debug("Start scan file: %s %s", content_provider.file_path, content_provider.info)

        if FilePathExtractor.is_find_by_ext_file(self.config, content_provider.file_type):
            # Skip the file scanning and create fake candidate because the extension is suspicious
            dummy_candidate = Candidate.get_dummy_candidate(self.config, content_provider.file_path,
                                                            content_provider.file_type, content_provider.info)
            candidates.append(dummy_candidate)

        elif self.config.depth > 0 and isinstance(content_provider, TextContentProvider):
            # Feature to scan files which might be containers
            data = Util.read_data(content_provider.file_path)
            if data:
                data_provider = DataContentProvider(data=data,
                                                    file_path=content_provider.file_path,
                                                    info=content_provider.file_path)
                candidates = self.data_scan(data_provider, self.config.depth, RECURSIVE_SCAN_LIMITATION)

        else:
            # Regular file scanning
            analysis_targets = content_provider.get_analysis_target()
            candidates = self.scanner.scan(analysis_targets)

        # finally return result from 'file_scan'
        return candidates

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def data_scan(self, data_provider: DataContentProvider, depth: int, recursive_limit_size: int) -> List[Candidate]:
        """Recursive function to scan files which might be containers like ZIP archives

            Args:
                data_provider: DataContentProvider object may be a container
                depth: maximal level of recursion
                recursive_limit_size: maximal bytes of opened files to prevent recursive zip-bomb attack
        """
        candidates: List[Candidate] = []
        logger.debug("Start data_scan: size=%d, depth=%d, limit=%d, path=%s, info=%s", len(data_provider.data), depth,
                     recursive_limit_size, data_provider.file_path, data_provider.info)

        if 0 > depth:
            # break recursion if maximal depth is reached
            logger.debug("bottom reached %s recursive_limit_size:%d", data_provider.file_path, recursive_limit_size)
            return candidates

        depth -= 1

        if FilePathExtractor.is_find_by_ext_file(self.config, data_provider.file_type):
            # Skip scanning file and makes fake candidate due the extension is suspicious
            dummy_candidate = Candidate.get_dummy_candidate(self.config, data_provider.file_path,
                                                            data_provider.file_type, data_provider.info)
            candidates.append(dummy_candidate)

        elif Util.is_zip(data_provider.data):
            # detected zip signature
            try:
                with zipfile.ZipFile(io.BytesIO(data_provider.data)) as zf:
                    for zfl in zf.infolist():
                        # skip directory
                        if "/" == zfl.filename[-1:]:
                            continue
                        if FilePathExtractor.check_exclude_file(self.config, zfl.filename):
                            continue
                        if 0 > recursive_limit_size - zfl.file_size:
                            logger.error(f"{zfl.filename}: size {zfl.file_size}"
                                         f" is over limit {recursive_limit_size} depth:{depth}")
                            continue
                        with zf.open(zfl) as f:
                            zip_content_provider = DataContentProvider(data=f.read(),
                                                                       file_path=data_provider.file_path,
                                                                       file_type=Util.get_extension(zfl.filename),
                                                                       info=f"{data_provider.info}|ZIP|{zfl.filename}")
                            # nevertheless use extracted data size
                            new_limit = recursive_limit_size - len(zip_content_provider.data)
                            zip_candidates = self.data_scan(zip_content_provider, depth, new_limit)
                            candidates.extend(zip_candidates)

            except Exception as zip_exc:
                # too many exception types might be produced with broken zip
                logger.error(f"{data_provider.file_path}:{zip_exc}")

        elif Util.is_gzip(data_provider.data):
            try:
                with gzip.open(io.BytesIO(data_provider.data)) as f:
                    new_path = data_provider.file_path if ".gz" != Util.get_extension(
                        data_provider.file_path) else data_provider.file_path[:-3]
                    gzip_content_provider = DataContentProvider(data=f.read(),
                                                                file_path=data_provider.file_path,
                                                                file_type=Util.get_extension(new_path),
                                                                info=f"{data_provider.info}|GZIP|{new_path}")
                    new_limit = recursive_limit_size - len(gzip_content_provider.data)
                    candidates = self.data_scan(gzip_content_provider, depth, new_limit)
            except Exception as gzip_exc:
                logger.error(f"{data_provider.file_path}:{gzip_exc}")

        else:
            # finally try scan the data via byte content provider
            byte_content_provider = ByteContentProvider(content=data_provider.data,
                                                        file_path=data_provider.file_path,
                                                        file_type=data_provider.file_type,
                                                        info=f"{data_provider.info}|RAW")
            analysis_targets = byte_content_provider.get_analysis_target()
            candidates = self.scanner.scan(analysis_targets)

        # finally return result from 'data_scan'
        return candidates

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def post_processing(self) -> None:
        """Machine learning validation for received credential candidates."""
        if self._use_ml_validation():
            logger.info("Run ML Validation")
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

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def export_results(self) -> None:
        """Save credential candidates to json file or print them to a console."""
        is_exported = False

        if self.json_filename:
            is_exported = True
            Util.json_dump([credential.to_json() for credential in self.credential_manager.get_credentials()],
                           file_path=self.json_filename)

        if self.xlsx_filename:
            is_exported = True
            data_list = []
            for credential in self.credential_manager.get_credentials():
                data_list.extend(credential.to_dict_list())
            df = pd.DataFrame(data=data_list)
            df.to_excel(self.xlsx_filename, index=False)

        if is_exported is False:
            for credential in self.credential_manager.get_credentials():
                print(credential)
