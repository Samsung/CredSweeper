import json
import logging
import multiprocessing
import signal
from pathlib import Path
from typing import Any, List, Optional, Union, Dict, Sequence, Tuple

import pandas as pd
from colorama import Style

# Directory of credsweeper sources MUST be placed before imports to avoid circular import error
APP_PATH = Path(__file__).resolve().parent

from credsweeper.scanner.scanner import Scanner
from credsweeper.common.constants import Severity, ThresholdPreset, DiffRowType, DEFAULT_ENCODING
from credsweeper.config.config import Config
from credsweeper.credentials.candidate import Candidate
from credsweeper.credentials.candidate_key import CandidateKey
from credsweeper.credentials.credential_manager import CredentialManager
from credsweeper.deep_scanner.deep_scanner import DeepScanner
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.file_handler.file_path_extractor import FilePathExtractor
from credsweeper.file_handler.abstract_provider import AbstractProvider
from credsweeper.ml_model.ml_validator import MlValidator
from credsweeper.utils.util import Util

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
                 json_filename: Union[None, str, Path] = None,
                 xlsx_filename: Union[None, str, Path] = None,
                 stdout: bool = False,
                 color: bool = False,
                 hashed: bool = False,
                 subtext: bool = False,
                 sort_output: bool = False,
                 use_filters: bool = True,
                 pool_count: int = 1,
                 ml_batch_size: Optional[int] = None,
                 ml_threshold: Union[int, float, ThresholdPreset] = ThresholdPreset.medium,
                 ml_config: Union[None, str, Path] = None,
                 ml_model: Union[None, str, Path] = None,
                 ml_providers: Optional[str] = None,
                 find_by_ext: bool = False,
                 pedantic: bool = False,
                 depth: int = 0,
                 doc: bool = False,
                 severity: Union[Severity, str] = Severity.INFO,
                 size_limit: Optional[str] = None,
                 exclude_lines: Optional[List[str]] = None,
                 exclude_values: Optional[List[str]] = None,
                 thrifty: bool = False,
                 log_level: Optional[str] = None) -> None:
        """Initialize Advanced credential scanner.

        Args:
            rule_path: optional str variable, path of rule config file
                validation was the grained candidate model on machine learning
            config_path: optional str variable, path of CredSweeper config file
                default built-in config is used if None
            json_filename: optional string variable, path to save result to json
            xlsx_filename: optional string variable, path to save result to xlsx
            stdout: print results to stdout
            color: print concise results to stdout with colorization
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
            pedantic: boolean - scan all files
            depth: int - how deep container files will be scanned
            doc: boolean - document-specific scanning
            severity: Severity - minimum severity level of rule
            size_limit: optional string integer or human-readable format to skip oversize files
            exclude_lines: lines to omit in scan. Will be added to the lines already in config
            exclude_values: values to omit in scan. Will be added to the values already in config
            thrifty: free provider resources after scan to reduce memory consumption
            log_level: str - level for pool initializer according logging levels (UPPERCASE)

        """
        self.pool_count: int = max(1, int(pool_count))
        if not (_severity := Severity.get(severity)):
            raise RuntimeError(f"Severity level provided: {severity}"
                               f" -- must be one of: {' | '.join([i.value for i in Severity])}")
        config_dict = self._get_config_dict(config_path=config_path,
                                            use_filters=use_filters,
                                            find_by_ext=find_by_ext,
                                            pedantic=pedantic,
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
        self.stdout = stdout
        self.color = color
        self.hashed = hashed
        self.subtext = subtext
        self.sort_output = sort_output
        self.ml_batch_size = ml_batch_size if ml_batch_size and 0 < ml_batch_size else 16
        self.ml_threshold = ml_threshold
        self.ml_config = ml_config
        self.ml_model = ml_model
        self.ml_providers = ml_providers
        self.__thrifty = thrifty
        self.__log_level = log_level
        self.__ml_validator: Optional[MlValidator] = None

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
            use_filters: bool,  #
            find_by_ext: bool,  #
            pedantic: bool,  #
            depth: int,  #
            doc: bool,  #
            severity: Severity,  #
            size_limit: Optional[str],  #
            exclude_lines: Optional[List[str]],  #
            exclude_values: Optional[List[str]]) -> Dict[str, Any]:
        config_dict = Util.json_load(self._get_config_path(config_path))
        config_dict["use_filters"] = use_filters
        config_dict["find_by_ext"] = find_by_ext
        config_dict["size_limit"] = size_limit
        config_dict["pedantic"] = pedantic
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
        if isinstance(self.ml_threshold, int) and 0 == self.ml_threshold:
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

    @property
    def ml_validator(self) -> MlValidator:
        """ml_validator getter"""
        if not self.__ml_validator:
            self.__ml_validator = MlValidator(
                threshold=self.ml_threshold,  #
                ml_config=self.ml_config,  #
                ml_model=self.ml_model,  #
                ml_providers=self.ml_providers,  #
            )
        if not self.__ml_validator:
            raise RuntimeError("MlValidator was not initialized!")
        return self.__ml_validator

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @staticmethod
    def pool_initializer(log_kwargs) -> None:
        """Ignore SIGINT in child processes."""
        logging.basicConfig(**log_kwargs)
        signal.signal(signal.SIGINT, signal.SIG_IGN)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def run(self, content_provider: AbstractProvider) -> int:
        """Run an analysis of 'content_provider' object.

        Args:
            content_provider: path objects to scan

        """
        _empty_list: Sequence[ContentProvider] = []
        file_extractors = content_provider.get_scannable_files(self.config) if content_provider else _empty_list
        if not file_extractors:
            logger.info(f"No scannable targets for {len(content_provider.paths)} paths")
            return 0
        self.scan(file_extractors)
        self.post_processing()
        # PatchesProvider has the attribute. Circular import error appears with using the isinstance
        change_type = content_provider.change_type if hasattr(content_provider, "change_type") else None
        self.export_results(change_type)
        return self.credential_manager.len_credentials()

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def scan(self, content_providers: Sequence[ContentProvider]) -> None:
        """Run scanning of files from an argument "content_providers".

        Args:
            content_providers: file objects to scan

        """
        if 1 < self.pool_count and 1 < len(content_providers):
            self.__multi_jobs_scan(content_providers)
        else:
            self.__single_job_scan(content_providers)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def __single_job_scan(self, content_providers: Sequence[ContentProvider]) -> None:
        """Performs scan in main thread"""
        logger.info(f"Scan for {len(content_providers)} providers")
        all_cred = self.files_scan(content_providers)
        self.credential_manager.set_credentials(all_cred)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def __multi_jobs_scan(self, content_providers: Sequence[ContentProvider]) -> None:
        """Performs scan with multiple jobs"""
        # use this separation to satisfy YAPF formatter
        yapfix = "%(asctime)s | %(levelname)s | %(processName)s:%(threadName)s | %(filename)s:%(lineno)s | %(message)s"
        log_kwargs = {"format": yapfix}
        if isinstance(self.__log_level, str):
            # is not None
            if "SILENCE" == self.__log_level:
                logging.addLevelName(60, "SILENCE")
            log_kwargs["level"] = self.__log_level
        pool_count = min(self.pool_count, len(content_providers))
        logger.info(f"Scan in {pool_count} processes for {len(content_providers)} providers")
        with multiprocessing.get_context("spawn").Pool(processes=pool_count,
                                                       initializer=CredSweeper.pool_initializer,
                                                       initargs=(log_kwargs,)) as pool:  # yapf: disable
            try:
                for scan_results in pool.imap_unordered(self.files_scan,
                                                        (content_providers[x::pool_count] for x in range(pool_count))):
                    for cred in scan_results:
                        self.credential_manager.add_credential(cred)
            except KeyboardInterrupt:
                pool.terminate()
                pool.join()
                raise
            pool.close()
            pool.join()

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def files_scan(self, content_providers: Sequence[ContentProvider]) -> List[Candidate]:
        """Auxiliary method for scan one sequence"""
        all_cred: List[Candidate] = []
        for provider in content_providers:
            candidates = self.file_scan(provider)
            if self.__thrifty:
                provider.free()
            all_cred.extend(candidates)
        logger.info(f"Completed: processed {len(content_providers)} providers with {len(all_cred)} candidates")
        return all_cred

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
                                                            content_provider.file_type, content_provider.info,
                                                            FilePathExtractor.FIND_BY_EXT_RULE)
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
                                candidate.ml_probability = probability[i]
                                new_cred_list.append(candidate)
                        else:
                            new_cred_list.append(candidate)
            else:
                logger.info("Skipping ML validation due not applicable")

            self.credential_manager.set_credentials(new_cred_list)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def export_results(self, change_type: Optional[DiffRowType] = None) -> None:
        """
        Save credential candidates to json file or print them to a console.

        Args:
            change_type: flag to know which file should be created for a patch
        """

        credentials = self.credential_manager.get_credentials()

        logger.info(f"Exporting {len(credentials)} credentials")

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
            json_path = Path(self.json_filename)
            if isinstance(change_type, DiffRowType):
                # add suffix for appropriated reports to create two files for the patch scan
                json_path = json_path.with_suffix(f".{change_type.value}{json_path.suffix}")
            with open(json_path, 'w', encoding=DEFAULT_ENCODING) as f:
                # use the approach to reduce total memory usage in case of huge data
                first_item = True
                f.write('[\n')
                for credential in credentials:
                    if first_item:
                        first_item = False
                    else:
                        f.write(",\n")
                    f.write(json.dumps(credential.to_json(hashed=self.hashed, subtext=self.subtext), indent=4))
                f.write("\n]")

        if self.xlsx_filename:
            data_list = []
            for credential in credentials:
                data_list.extend(credential.to_dict_list(hashed=self.hashed, subtext=self.subtext))
            df = pd.DataFrame(data=data_list)
            if isinstance(change_type, DiffRowType):
                if Path(self.xlsx_filename).exists():
                    with pd.ExcelWriter(self.xlsx_filename, mode='a', engine="openpyxl",
                                        if_sheet_exists="replace") as writer:
                        df.to_excel(writer, sheet_name=change_type.value, index=False)
                else:
                    df.to_excel(self.xlsx_filename, sheet_name=change_type.value, index=False)
            else:
                df.to_excel(self.xlsx_filename, sheet_name="report", index=False)

        if self.color:
            for credential in credentials:
                for line_data in credential.line_data_list:
                    # bright rule name and path or info
                    if isinstance(credential.ml_probability, float):
                        ml_probability_info = f" {credential.ml_probability:.6f}"
                    else:
                        ml_probability_info = ""
                    print(Style.BRIGHT + credential.rule_name +
                          f" {line_data.info or line_data.path}:{line_data.line_num}{ml_probability_info}" +
                          Style.RESET_ALL)
                    print(line_data.get_colored_line(hashed=self.hashed, subtext=self.subtext))

        if self.stdout:
            for credential in credentials:
                print(credential.to_str(hashed=self.hashed, subtext=self.subtext))
