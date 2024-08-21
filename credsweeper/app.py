import logging
import multiprocessing
import signal
from pathlib import Path
from typing import Any, List, Optional, Union, Dict, Sequence, Tuple

import pandas as pd

# Directory of credsweeper sources MUST be placed before imports to avoid circular import error
APP_PATH = Path(__file__).resolve().parent

from credsweeper.common.constants import KeyValidationOption, Severity, ThresholdPreset
from credsweeper.config import Config
from credsweeper.credentials import Candidate, CredentialManager, CandidateKey
from credsweeper.deep_scanner.deep_scanner import DeepScanner
from credsweeper.file_handler.diff_content_provider import DiffContentProvider
from credsweeper.file_handler.file_path_extractor import FilePathExtractor
from credsweeper.file_handler.abstract_provider import AbstractProvider
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
                 rule_path: Union[None, str, Path] = None,
                 config_path: Optional[str] = None,
                 api_validation: bool = False,
                 json_filename: Union[None, str, Path] = None,
                 xlsx_filename: Union[None, str, Path] = None,
                 hashed: bool = False,
                 subtext: bool = False,
                 sort_output: bool = False,
                 use_filters: bool = True,
                 pool_count: int = 1,
                 ml_batch_size: Optional[int] = None,
                 ml_threshold: Union[float, ThresholdPreset] = ThresholdPreset.medium,
                 ml_config: Union[None, str, Path] = None,
                 ml_model: Union[None, str, Path] = None,
                 ml_providers: Optional[str] = None,
                 find_by_ext: bool = False,
                 depth: int = 0,
                 doc: bool = False,
                 severity: Union[Severity, str] = Severity.INFO,
                 size_limit: Optional[str] = None,
                 exclude_lines: Optional[List[str]] = None,
                 exclude_values: Optional[List[str]] = None,
                 log_level: Optional[str] = None) -> None:
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
            hashed: use hash of line, value and variable instead plain text
            subtext: use subtext of line near variable-value like it performed in ML
            use_filters: boolean variable, specifying the need of rule filters
            pool_count: int value, number of parallel processes to use
            ml_batch_size: int value, size of the batch for model inference
            ml_threshold: float or string value to specify threshold for the ml model
            ml_config: str or Path to set custom config of ml model
            ml_model: str or Path to set custom ml model
            ml_providers: str - comma separated list with providers
            find_by_ext: boolean - files will be reported by extension
            depth: int - how deep container files will be scanned
            doc: boolean - document-specific scanning
            severity: Severity - minimum severity level of rule
            size_limit: optional string integer or human-readable format to skip oversize files
            exclude_lines: lines to omit in scan. Will be added to the lines already in config
            exclude_values: values to omit in scan. Will be added to the values already in config
            log_level: str - level for pool initializer according logging levels (UPPERCASE)

        """
        self.pool_count: int = int(pool_count) if int(pool_count) > 1 else 1
        if not (_severity := Severity.get(severity)):
            raise RuntimeError(f"Severity level provided: {severity}"
                               f" -- must be one of: {' | '.join([i.value for i in Severity])}")
        config_dict = self._get_config_dict(config_path=config_path,
                                            api_validation=api_validation,
                                            use_filters=use_filters,
                                            find_by_ext=find_by_ext,
                                            depth=depth,
                                            doc=doc,
                                            severity=_severity,
                                            size_limit=size_limit,
                                            exclude_lines=exclude_lines,
                                            exclude_values=exclude_values)
        self.config = Config(config_dict)
        self.scanner = Scanner(self.config, rule_path)
        self.deep_scanner = DeepScanner(self.config, self.scanner)
        self.credential_manager = CredentialManager()
        self.json_filename: Union[None, str, Path] = json_filename
        self.xlsx_filename: Union[None, str, Path] = xlsx_filename
        self.hashed = hashed
        self.subtext = subtext
        self.sort_output = sort_output
        self.ml_batch_size = ml_batch_size if ml_batch_size and 0 < ml_batch_size else 16
        self.ml_threshold = ml_threshold
        self.ml_config = ml_config
        self.ml_model = ml_model
        self.ml_providers = ml_providers
        self.ml_validator = None
        self.__log_level = log_level

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @staticmethod
    def _get_config_path(config_path: Optional[str]) -> Path:
        if config_path:
            return Path(config_path)
        else:
            return APP_PATH / "secret" / "config.json"

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def _get_config_dict(
            self,  #
            config_path: Optional[str],  #
            api_validation: bool,  #
            use_filters: bool,  #
            find_by_ext: bool,  #
            depth: int,  #
            doc: bool,  #
            severity: Severity,  #
            size_limit: Optional[str],  #
            exclude_lines: Optional[List[str]],  #
            exclude_values: Optional[List[str]]) -> Dict[str, Any]:
        config_dict = Util.json_load(self._get_config_path(config_path))
        config_dict["validation"] = {}
        config_dict["validation"]["api_validation"] = api_validation
        config_dict["use_filters"] = use_filters
        config_dict["find_by_ext"] = find_by_ext
        config_dict["size_limit"] = size_limit
        config_dict["depth"] = depth
        config_dict["doc"] = doc
        config_dict["severity"] = severity.value

        if exclude_lines is not None:
            config_dict["exclude"]["lines"] = config_dict["exclude"].get("lines", []) + exclude_lines
        if exclude_values is not None:
            config_dict["exclude"]["values"] = config_dict["exclude"].get("values", []) + exclude_values

        return config_dict  # type: ignore

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def _use_ml_validation(self) -> bool:
        if isinstance(self.ml_threshold, (float, int)) and 0 >= self.ml_threshold:
            logger.info("ML validation is disabled")
            return False
        if not self.credential_manager.candidates:
            logger.info("Skip ML validation because no candidates were found")
            return False
        for i in self.credential_manager.candidates:
            if i.use_ml:
                # any() or all() is not used to speedup
                return True
        logger.info("Skip ML validation because no candidates support it")
        return False

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
            self.__ml_validator: MlValidator = MlValidator(
                threshold=self.ml_threshold,  #
                ml_config=self.ml_config,  #
                ml_model=self.ml_model,  #
                ml_providers=self.ml_providers,  #
            )
        assert self.__ml_validator, "self.__ml_validator was not initialized"
        return self.__ml_validator

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @ml_validator.setter
    def ml_validator(self, _ml_validator: Optional[MlValidator]) -> None:
        """ml_validator setter"""
        self.__ml_validator = _ml_validator

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @staticmethod
    def pool_initializer(log_kwargs) -> None:
        """Ignore SIGINT in child processes."""
        logging.basicConfig(**log_kwargs)
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

    def run(self, content_provider: AbstractProvider) -> int:
        """Run an analysis of 'content_provider' object.

        Args:
            content_provider: path objects to scan

        """
        _empty_list: Sequence[Union[DiffContentProvider, TextContentProvider]] = []
        file_extractors: Sequence[Union[DiffContentProvider, TextContentProvider]] = \
            content_provider.get_scannable_files(self.config) if content_provider else _empty_list
        logger.info(f"Start Scanner for {len(file_extractors)} providers")
        self.scan(file_extractors)
        self.post_processing()
        self.export_results()

        return len(self.credential_manager.get_credentials())

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def scan(self, content_providers: Sequence[Union[DiffContentProvider, TextContentProvider]]) -> None:
        """Run scanning of files from an argument "content_providers".

        Args:
            content_providers: file objects to scan

        """
        if 1 < self.pool_count:
            self.__multi_jobs_scan(content_providers)
        else:
            self.__single_job_scan(content_providers)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def __single_job_scan(self, content_providers: Sequence[Union[DiffContentProvider, TextContentProvider]]) -> None:
        """Performs scan in main thread"""
        all_cred = self.files_scan(content_providers)
        if self.config.api_validation:
            api_validation = ApplyValidation()
            for cred in all_cred:
                logger.info("Run API Validation")
                cred.api_validation = api_validation.validate(cred)
                self.credential_manager.add_credential(cred)
        else:
            self.credential_manager.set_credentials(all_cred)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def __multi_jobs_scan(self, content_providers: Sequence[Union[DiffContentProvider, TextContentProvider]]) -> None:
        """Performs scan with multiple jobs"""
        # use this separation to satisfy YAPF formatter
        yapfix = "%(asctime)s | %(levelname)s | %(processName)s:%(threadName)s | %(filename)s:%(lineno)s | %(message)s"
        log_kwargs = {"format": yapfix}
        if isinstance(self.__log_level, str):
            # is not None
            if "SILENCE" == self.__log_level:
                logging.addLevelName(60, "SILENCE")
            log_kwargs["level"] = self.__log_level
        # providers_map: List[Sequence[Union[DiffContentProvider, TextContentProvider]]] = \
        #     [content_providers[x::self.pool_count] for x in range(self.pool_count)]
        with multiprocessing.get_context("spawn").Pool(processes=self.pool_count,
                                                       initializer=self.pool_initializer,
                                                       initargs=(log_kwargs, )) as pool:
            try:
                for scan_results in pool.imap_unordered(self.files_scan, (content_providers[x::self.pool_count]
                                                                          for x in range(self.pool_count))):
                    for cred in scan_results:
                        self.credential_manager.add_credential(cred)
                if self.config.api_validation:
                    logger.info("Run API Validation")
                    api_validation = ApplyValidation()
                    api_validation.validate_credentials(pool, self.credential_manager)
            except KeyboardInterrupt:
                pool.terminate()
                pool.join()
                raise
            pool.close()
            pool.join()

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def files_scan(
            self,  #
            content_providers: Sequence[Union[DiffContentProvider, TextContentProvider]]) -> List[Candidate]:
        """Auxiliary method for scan one sequence"""
        all_cred: List[Candidate] = []
        for i in content_providers:
            candidates = self.file_scan(i)
            all_cred.extend(candidates)
        logger.info(f"Completed: processed {len(content_providers)} providers with {len(all_cred)} candidates")
        return all_cred

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def file_scan(self, content_provider: Union[DiffContentProvider, TextContentProvider]) -> List[Candidate]:
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

        else:
            if self.config.depth or self.config.doc:
                # deep scan with possible data representation
                candidates = self.deep_scanner.scan(content_provider, self.config.depth, self.config.size_limit)
            else:
                if content_provider.file_type not in self.config.exclude_containers:
                    # Regular file scanning
                    candidates = self.scanner.scan(content_provider)

        # finally return result from 'file_scan'
        return candidates

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def post_processing(self) -> None:
        """Machine learning validation for received credential candidates."""
        if purged := self.credential_manager.purge_duplicates():
            logger.info(f"Purged {purged} duplicates")
        if self._use_ml_validation():
            logger.info(f"Grouping {len(self.credential_manager.candidates)} candidates")
            new_cred_list: List[Candidate] = []
            cred_groups = self.credential_manager.group_credentials()
            ml_cred_groups: List[Tuple[CandidateKey, List[Candidate]]] = []
            for group_key, group_candidates in cred_groups.items():
                # Analyze with ML if any candidate in group require ML
                for candidate in group_candidates:
                    if candidate.use_ml:
                        ml_cred_groups.append((group_key, group_candidates))
                        break
                else:
                    # all candidates do not require ML
                    new_cred_list.extend(group_candidates)

            # prevent extra ml_validator creation if ml_cred_groups is empty
            if ml_cred_groups:
                logger.info(f"Run ML Validation for {len(ml_cred_groups)} groups")
                is_cred, probability = self.ml_validator.validate_groups(ml_cred_groups, self.ml_batch_size)
                for i, (_, group_candidates) in enumerate(ml_cred_groups):
                    for candidate in group_candidates:
                        if candidate.use_ml:
                            if is_cred[i]:
                                candidate.ml_validation = KeyValidationOption.VALIDATED_KEY
                                candidate.ml_probability = probability[i]
                                new_cred_list.append(candidate)
                        else:
                            candidate.ml_validation = KeyValidationOption.NOT_AVAILABLE
                            new_cred_list.append(candidate)
            else:
                logger.info("Skipping ML validation due not applicable")

            self.credential_manager.set_credentials(new_cred_list)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def export_results(self) -> None:
        """Save credential candidates to json file or print them to a console."""
        is_exported = False

        credentials = self.credential_manager.get_credentials()

        if self.sort_output:
            credentials.sort(key=lambda x: (  #
                x.line_data_list[0].path,  #
                x.line_data_list[0].line_num,  #
                x.severity,  #
                x.rule_name,  #
                x.line_data_list[0].value_start,  #
                x.line_data_list[0].value_end  #
            ))

        if self.json_filename:
            is_exported = True
            Util.json_dump([credential.to_json(hashed=self.hashed, subtext=self.subtext) for credential in credentials],
                           file_path=self.json_filename)

        if self.xlsx_filename:
            is_exported = True
            data_list = []
            for credential in credentials:
                data_list.extend(credential.to_dict_list(hashed=self.hashed, subtext=self.subtext))
            df = pd.DataFrame(data=data_list)
            df.to_excel(self.xlsx_filename, index=False)

        if is_exported is False:
            for credential in credentials:
                print(credential.to_str(hashed=self.hashed, subtext=self.subtext))
