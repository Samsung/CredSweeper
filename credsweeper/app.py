import bz2
import gzip
import io
import itertools
import logging
import multiprocessing
import os
import signal
import sys
import tarfile
import zipfile
from typing import List, Optional, Union, Tuple, Any

import pandas as pd
from pdfminer.high_level import extract_pages
from pdfminer.layout import LAParams, LTText, LTItem

from credsweeper.common.constants import KeyValidationOption, ThresholdPreset, RECURSIVE_SCAN_LIMITATION, \
    DEFAULT_ENCODING
from credsweeper.config import Config
from credsweeper.credentials import Candidate, CredentialManager
from credsweeper.credentials.augment_candidates import augment_candidates
from credsweeper.file_handler.byte_content_provider import ByteContentProvider
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.file_handler.data_content_provider import DataContentProvider, MIN_DATA_LEN
from credsweeper.file_handler.diff_content_provider import DiffContentProvider
from credsweeper.file_handler.file_path_extractor import FilePathExtractor
from credsweeper.file_handler.files_provider import FilesProvider
from credsweeper.file_handler.string_content_provider import StringContentProvider
from credsweeper.file_handler.struct_content_provider import StructContentProvider
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

        else:
            # Regular file scanning
            if content_provider.file_type not in self.config.exclude_containers:
                analysis_targets = content_provider.get_analysis_target()
                candidates.extend(self.scanner.scan(analysis_targets))

            # deep scan with possibly data representation
            if self.config.depth:
                data: Optional[bytes] = None
                if isinstance(content_provider, TextContentProvider):
                    # Feature to scan files which might be containers
                    data = Util.read_data(content_provider.file_path)
                elif isinstance(content_provider, DiffContentProvider) and content_provider.diff:
                    # Feature to scan binary diffs
                    diff = content_provider.diff[0].get("line")
                    # the check for legal fix mypy issue
                    if isinstance(diff, bytes):
                        data = diff
                else:
                    logger.warning(f"Content provider {type(content_provider)} does not support deep scan")

                if data:
                    new_size_limit = self.config.size_limit if self.config.size_limit else RECURSIVE_SCAN_LIMITATION
                    new_size_limit -= len(data)
                    data_provider = DataContentProvider(data=data,
                                                        file_path=content_provider.file_path,
                                                        file_type=content_provider.file_type,
                                                        info=content_provider.file_path)
                    # iterate for all possibly scanner methods WITHOUT ByteContentProvider for TextContentProvider
                    scan_methods = self.__get_scan_methods(data)
                    if isinstance(content_provider, TextContentProvider) and self.__byte_scan in scan_methods:
                        scan_methods.remove(self.__byte_scan)
                    for scan_method in scan_methods:
                        new_candidates = scan_method(
                            data_provider,  #
                            self.config.depth - 1,  #
                            new_size_limit)
                        augment_candidates(candidates, new_candidates)

        # finally return result from 'file_scan'
        return candidates

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def recursive_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> List[Candidate]:
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
        else:
            # iterate for all possibly scanner methods
            for scan_method in self.__get_scan_methods(data_provider.data):
                new_candidates = scan_method(data_provider, depth, recursive_limit_size)
                augment_candidates(candidates, new_candidates)

        return candidates

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def struct_scan(
            self,  #
            struct_provider: StructContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> List[Candidate]:
        """Recursive function to scan structured data

            Args:
                struct_provider: DataContentProvider object may be a container
                depth: maximal level of recursion
                recursive_limit_size: maximal bytes of opened files to prevent recursive zip-bomb attack
        """
        candidates: List[Candidate] = []
        logger.debug("Start struct_scan: depth=%d, limit=%d, path=%s, info=%s", depth, recursive_limit_size,
                     struct_provider.file_path, struct_provider.info)

        if 0 > depth:
            # break recursion if maximal depth is reached
            logger.debug("bottom reached %s recursive_limit_size:%d", struct_provider.file_path, recursive_limit_size)
            return candidates

        depth -= 1

        items: List[Tuple[Union[int, str], Any]] = []
        if isinstance(struct_provider.struct, dict):
            items = list(struct_provider.struct.items())
        elif isinstance(struct_provider.struct, list) or isinstance(struct_provider.struct, tuple):
            items = list(enumerate(struct_provider.struct))
        else:
            logger.error("Not supported type:%s val:%s", str(type(struct_provider.struct)), str(struct_provider.struct))

        for key, value in items:
            if isinstance(value, dict) or isinstance(value, list) or isinstance(value, tuple):
                val_struct_provider = StructContentProvider(struct=value,
                                                            file_path=struct_provider.file_path,
                                                            file_type=struct_provider.file_type,
                                                            info=f"{struct_provider.info}|STRUCT:{key}")
                candidates.extend(self.struct_scan(val_struct_provider, depth, recursive_limit_size))

            elif isinstance(value, bytes):
                bytes_struct_provider = DataContentProvider(data=value,
                                                            file_path=struct_provider.file_path,
                                                            file_type=struct_provider.file_type,
                                                            info=f"{struct_provider.info}|BYTES:{key}")
                new_limit = recursive_limit_size - len(value)
                new_candidates = self.recursive_scan(bytes_struct_provider, depth, new_limit)
                candidates.extend(new_candidates)

            elif isinstance(value, str):
                data = value.encode(encoding=DEFAULT_ENCODING, errors='replace')
                str_struct_provider = DataContentProvider(data=data,
                                                          file_path=struct_provider.file_path,
                                                          file_type=struct_provider.file_type,
                                                          info=f"{struct_provider.info}|STRING:{key}")
                new_limit = recursive_limit_size - len(str_struct_provider.data)
                new_candidates = self.recursive_scan(str_struct_provider, depth, new_limit)
                candidates.extend(new_candidates)

                # use key = "value" scan for common cases like in Python code
                if isinstance(struct_provider.struct, dict):
                    str_provider = StringContentProvider([f"{key} = \"{value}\""],
                                                         file_path=struct_provider.file_path,
                                                         file_type=".py",
                                                         info=f"{struct_provider.info}|STRING:`{key} = \"{value}\"`")
                    str_analysis_targets = str_provider.get_analysis_target()
                    new_candidates = self.scanner.scan(str_analysis_targets)
                    augment_candidates(candidates, new_candidates)
            elif isinstance(value, int) or isinstance(value, float):
                pass
            else:
                logger.debug("Not supported type:%s value(%s)", str(type(value)), str(value))

        return candidates

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def __zip_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> List[Candidate]:
        """Extracts files one by one from zip archives and launch data_scan"""
        candidates = []
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
                        zip_candidates = self.recursive_scan(zip_content_provider, depth, new_limit)
                        candidates.extend(zip_candidates)
        except Exception as zip_exc:
            # too many exception types might be produced with broken zip
            logger.error(f"{data_provider.file_path}:{zip_exc}")
        return candidates

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def __bzip2_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> List[Candidate]:
        """Extracts data from bzip2 archive and launch data_scan"""
        candidates = []
        try:
            new_path = data_provider.file_path if ".bz2" != Util.get_extension(
                data_provider.file_path) else data_provider.file_path[:-4]
            bzip2_content_provider = DataContentProvider(data=bz2.decompress(data_provider.data),
                                                         file_path=data_provider.file_path,
                                                         file_type=Util.get_extension(new_path),
                                                         info=f"{data_provider.info}|BZIP2|{new_path}")
            new_limit = recursive_limit_size - len(bzip2_content_provider.data)
            bzip2_candidates = self.recursive_scan(bzip2_content_provider, depth, new_limit)
            candidates.extend(bzip2_candidates)
        except Exception as bzip2_exc:
            logger.error(f"{data_provider.file_path}:{bzip2_exc}")
        return candidates

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def __tar_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> List[Candidate]:
        """Extracts files one by one from tar archive and launch data_scan"""
        candidates = []
        try:
            with tarfile.TarFile(fileobj=io.BytesIO(data_provider.data)) as tf:
                for tfi in tf.getmembers():
                    # skip directory
                    if not tfi.isreg():
                        continue
                    if FilePathExtractor.check_exclude_file(self.config, tfi.name):
                        continue
                    if 0 > recursive_limit_size - tfi.size:
                        logger.error(f"{tfi.name}: size {tfi.size}"
                                     f" is over limit {recursive_limit_size} depth:{depth}")
                        continue
                    with tf.extractfile(tfi) as f:
                        tar_content_provider = DataContentProvider(data=f.read(),
                                                                   file_path=data_provider.file_path,
                                                                   file_type=Util.get_extension(tfi.name),
                                                                   info=f"{data_provider.info}|TAR|{tfi.name}")
                        # nevertheless use extracted data size
                        new_limit = recursive_limit_size - len(tar_content_provider.data)
                        tar_candidates = self.recursive_scan(tar_content_provider, depth, new_limit)
                        candidates.extend(tar_candidates)
        except Exception as tar_exc:
            # too many exception types might be produced with broken tar
            logger.error(f"{data_provider.file_path}:{tar_exc}")
        return candidates

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    def __gzip_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> List[Candidate]:
        """Extracts data from gzip archive and launch data_scan"""
        candidates = []
        try:
            with gzip.open(io.BytesIO(data_provider.data)) as f:
                new_path = data_provider.file_path if ".gz" != Util.get_extension(
                    data_provider.file_path) else data_provider.file_path[:-3]
                gzip_content_provider = DataContentProvider(data=f.read(),
                                                            file_path=data_provider.file_path,
                                                            file_type=Util.get_extension(new_path),
                                                            info=f"{data_provider.info}|GZIP|{new_path}")
                new_limit = recursive_limit_size - len(gzip_content_provider.data)
                gzip_candidates = self.recursive_scan(gzip_content_provider, depth, new_limit)
                candidates.extend(gzip_candidates)
        except Exception as gzip_exc:
            logger.error(f"{data_provider.file_path}:{gzip_exc}")
        return candidates

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def __pdf_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> List[Candidate]:
        """Extracts text from PDF elements and whole text, then launch data_scan"""
        candidates = []
        # PyPDF2 - https://github.com/py-pdf/pypdf/issues/1328 text in table is merged without spaces
        # pdfminer.six - splits text in table to many lines. Allows to walk through elements
        try:
            pdf_lines = []
            for page in extract_pages(io.BytesIO(data_provider.data), laparams=LAParams()):
                for element in page:
                    if isinstance(element, LTText):
                        element_text = element.get_text().strip()
                        if element_text:
                            element_candidates = []
                            if MIN_DATA_LEN < len(element_text):
                                pdf_content_provider = DataContentProvider(
                                    data=element_text.encode(),
                                    file_path=data_provider.file_path,
                                    file_type=".xml",
                                    info=f"{data_provider.info}|PDF:{page.pageid}")
                                new_limit = recursive_limit_size - len(pdf_content_provider.data)
                                element_candidates = self.recursive_scan(pdf_content_provider, depth, new_limit)
                                candidates.extend(element_candidates)
                            if not element_candidates:
                                # skip to decrease duplicates of candidates
                                pdf_lines.append(element_text)
                    elif isinstance(element, LTItem):
                        pass
                    else:
                        logger.error(f"Unsupported {element}")
            string_data_provider = StringContentProvider(lines=pdf_lines,
                                                         file_path=data_provider.file_path,
                                                         file_type=".xml",
                                                         info=f"{data_provider.info}|PDF")
            analysis_targets = string_data_provider.get_analysis_target()
            pdf_candidates = self.scanner.scan(analysis_targets)
            candidates.extend(pdf_candidates)
        except Exception as pdf_exc:
            logger.error(f"{data_provider.file_path}:{pdf_exc}")
        return candidates

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def __enc_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> List[Candidate]:
        """Tries to decode data from base64 encode to bytes and scan as bytes again"""
        if data_provider.represent_as_encoded():
            decoded_data_provider = DataContentProvider(data=data_provider.decoded,
                                                        file_path=data_provider.file_path,
                                                        file_type=data_provider.file_type,
                                                        info=f"{data_provider.info}|ENCODED")
            new_limit = recursive_limit_size - len(decoded_data_provider.data)
            return self.recursive_scan(decoded_data_provider, depth, new_limit)
        return []

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    def __html_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> List[Candidate]:
        """Tries to represent data as html text and scan as text lines"""
        if data_provider.represent_as_html():
            string_data_provider = StringContentProvider(lines=data_provider.lines,
                                                         line_numbers=data_provider.line_numbers,
                                                         file_path=data_provider.file_path,
                                                         file_type=".xml",
                                                         info=f"{data_provider.info}|HTML")
            analysis_targets = string_data_provider.get_analysis_target()
            return self.scanner.scan(analysis_targets)
        return []

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    def __xml_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> List[Candidate]:
        """Tries to represent data as xml text and scan as text lines"""
        if data_provider.represent_as_xml():
            string_data_provider = StringContentProvider(lines=data_provider.lines,
                                                         line_numbers=data_provider.line_numbers,
                                                         file_path=data_provider.file_path,
                                                         file_type=".xml",
                                                         info=f"{data_provider.info}|XML")
            analysis_targets = string_data_provider.get_analysis_target()
            return self.scanner.scan(analysis_targets)
        return []

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def __lang_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> List[Candidate]:
        """Tries to represent data as markup language and scan as structure"""
        if data_provider.represent_as_structure():
            struct_data_provider = StructContentProvider(struct=data_provider.structure,
                                                         file_path=data_provider.file_path,
                                                         file_type=data_provider.file_type,
                                                         info=f"{data_provider.info}|STRUCT")
            return self.struct_scan(struct_data_provider, depth, recursive_limit_size)
        return []

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def __byte_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> List[Candidate]:
        """Tries to represent data as plain text with splitting by lines and scan as text lines"""
        byte_content_provider = ByteContentProvider(content=data_provider.data,
                                                    file_path=data_provider.file_path,
                                                    file_type=data_provider.file_type,
                                                    info=f"{data_provider.info}|RAW")
        analysis_targets = byte_content_provider.get_analysis_target()
        return self.scanner.scan(analysis_targets)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def __get_scan_methods(self, data: bytes) -> List[Any]:
        """Returns possibly scan methods for the data depends on content"""
        scan_methods = []
        if Util.is_zip(data):
            scan_methods.append(self.__zip_scan)
            # probably, there might be a docx, xlxs and so on.
            # It might be scanned with text representation in third-party libraries.
        elif Util.is_bzip2(data):
            scan_methods.append(self.__bzip2_scan)
        elif Util.is_tar(data):
            scan_methods.append(self.__tar_scan)
        elif Util.is_gzip(data):
            scan_methods.append(self.__gzip_scan)
        elif Util.is_pdf(data):
            scan_methods.append(self.__pdf_scan)
        else:
            scan_methods = [self.__enc_scan, self.__html_scan, self.__xml_scan, self.__lang_scan, self.__byte_scan]
        return scan_methods

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
