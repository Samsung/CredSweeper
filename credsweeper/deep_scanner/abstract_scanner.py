import contextlib
import datetime
import io
import logging
from abc import abstractmethod, ABC
from bz2 import BZ2File
from collections.abc import Sized
from gzip import GzipFile
from lzma import LZMAFile
from types import CodeType, EllipsisType
from typing import List, Optional, Tuple, Any, Generator, Union

from credsweeper.common.constants import RECURSIVE_SCAN_LIMITATION, MIN_DATA_LEN, DEFAULT_ENCODING, UTF_8, \
    MIN_VALUE_LENGTH
from credsweeper.config.config import Config
from credsweeper.credentials.augment_candidates import augment_candidates
from credsweeper.credentials.candidate import Candidate
from credsweeper.file_handler.byte_content_provider import ByteContentProvider
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.descriptor import Descriptor
from credsweeper.file_handler.diff_content_provider import DiffContentProvider
from credsweeper.file_handler.file_path_extractor import FilePathExtractor
from credsweeper.file_handler.string_content_provider import StringContentProvider
from credsweeper.file_handler.struct_content_provider import StructContentProvider
from credsweeper.file_handler.text_content_provider import TextContentProvider
from credsweeper.scanner.scanner import Scanner
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class AbstractScanner(ABC):
    """Base abstract class for all recursive scanners"""

    @property
    @abstractmethod
    def config(self) -> Config:
        """Abstract property to be defined in DeepScanner"""
        raise NotImplementedError(__name__)

    @property
    @abstractmethod
    def scanner(self) -> Scanner:
        """Abstract property to be defined in DeepScanner"""
        raise NotImplementedError(__name__)

    @staticmethod
    @abstractmethod
    def match(data: bytes | bytearray) -> bool:
        """Abstract method for any deep scanner"""
        raise NotImplementedError(__name__)

    @abstractmethod
    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Abstract method to be defined in DeepScanner"""
        raise NotImplementedError(__name__)

    @staticmethod
    @abstractmethod
    def get_deep_scanners(data: bytes, descriptor: Descriptor, depth: int, limit: int) -> Tuple[List[Any], List[Any]]:
        """Returns possibly scan methods for the data depends on content and fallback scanners"""
        raise NotImplementedError(__name__)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def recursive_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int = 0,  #
            recursive_limit_size: int = 0) -> List[Candidate]:
        """Recursive function to scan files which might be containers like ZIP archives

            Args:
                data_provider: DataContentProvider object may be a container
                depth: maximal level of recursion
                recursive_limit_size: maximal bytes of opened files to prevent recursive zip-bomb attack
        """
        candidates: List[Candidate] = []
        if 0 > depth:
            # break recursion if maximal depth is reached
            logger.debug("Bottom reached %s recursive_limit_size:%d", data_provider.file_path, recursive_limit_size)
            return candidates
        depth -= 1
        data_size = len(data_provider.data)
        if MIN_DATA_LEN > data_size:
            # break recursion for minimal data size
            logger.debug("Too small data: size=%d, depth=%d, limit=%d, path=%s, info=%s", data_size, depth,
                         recursive_limit_size, data_provider.file_path, data_provider.info)
            return candidates
        recursive_limit_size -= data_size
        if MIN_DATA_LEN > recursive_limit_size:
            # break recursion for exhausted size limit
            logger.debug("Recursive limit exhausted: size=%d, depth=%d, limit=%d, path=%s, info=%s", data_size, depth,
                         recursive_limit_size, data_provider.file_path, data_provider.info)
            return candidates
        logger.debug("Start data_scan: size=%d, depth=%d, limit=%d, path=%s, info=%s", data_size, depth,
                     recursive_limit_size, data_provider.file_path, data_provider.info)

        if FilePathExtractor.is_find_by_ext_file(self.config, data_provider.file_type):
            # Skip scanning file and makes fake candidate due the extension is suspicious
            dummy_candidate = Candidate.get_dummy_candidate(self.config, data_provider.file_path,
                                                            data_provider.file_type, data_provider.info,
                                                            FilePathExtractor.FIND_BY_EXT_RULE)
            candidates.append(dummy_candidate)
        else:
            new_candidates = self.deep_scan_with_fallback(data_provider, depth, recursive_limit_size)
            augment_candidates(candidates, new_candidates)

        return candidates

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @staticmethod
    def key_value_combination(structure: dict) -> Generator[Tuple[Any, Any], None, None]:
        """Combine items by `key` and `value` from a dictionary for augmentation
        {..., "key": "api_key", "value": "XXXXXXX", ...} -> ("api_key", "XXXXXXX")

        """
        for key_id in ("key", "KEY", "Key"):
            if key_id in structure:
                struct_key = structure.get(key_id)
                break
        else:
            struct_key = None
        if isinstance(struct_key, bytes):
            # sqlite table may produce bytes for `key`
            with contextlib.suppress(UnicodeError):
                struct_key = struct_key.decode(UTF_8)
        # only str type is common used for the augmentation
        if struct_key and isinstance(struct_key, str):
            for value_id in ("value", "VALUE", "Value"):
                if value_id in structure:
                    struct_value = structure.get(value_id)
                    if struct_value and isinstance(struct_value, (str, bytes)):
                        yield struct_key, struct_value
                        # break in successful case
                        break

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @staticmethod
    def structure_size(structure: Any) -> int:
        """Calculates approximated size of structure data"""
        size = len(structure) if isinstance(structure, Sized) else 0
        if isinstance(structure, dict):
            for key, value in structure.items():
                size += AbstractScanner.structure_size(key)
                size += AbstractScanner.structure_size(value)
        elif isinstance(structure, (list, tuple)):
            size += sum(AbstractScanner.structure_size(x) for x in structure)
        return size

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @staticmethod
    def structure_processing(structure: Any) -> Generator[Tuple[Any, Any], None, None]:
        """Yields pair `key, value` from given structure if applicable"""
        if isinstance(structure, dict):
            # transform dictionary to list
            for key, value in structure.items():
                if not value:
                    # skip empty values
                    continue
                if isinstance(value, (list, tuple)):
                    if 1 == len(value):
                        # simplify some structures like YAML when single item in new line is a value
                        yield key, value[0]
                        continue
                # all other data will be precessed in next code
                yield key, value
            yield from AbstractScanner.key_value_combination(structure)
        elif isinstance(structure, (list, tuple)):
            # enumerate the items to fit for return structure
            for key, value in enumerate(structure):
                yield key, value
        elif isinstance(structure, CodeType):
            # enumerate the items to fit for return structure
            for key, value in enumerate(structure.co_consts):
                if isinstance(value, CodeType):
                    yield from AbstractScanner.structure_processing(value)
                elif value:
                    yield key, value
        else:
            logger.warning("Not supported type:%s val:%s", str(type(structure)), repr(structure))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def structure_scan(
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

        structure_size = AbstractScanner.structure_size(struct_provider.struct)
        recursive_limit_size -= structure_size
        if 0 > depth or MIN_DATA_LEN > recursive_limit_size:
            # break recursion if maximal depth is reached or recursive_limit_size almost exhausted
            logger.debug("Stopping recursion on %s depth:%d, recursive_limit_size:%d", struct_provider.file_path, depth,
                         recursive_limit_size)
            return candidates
        depth -= 1

        augmented_lines_for_keyword_rules = []
        for key, value in AbstractScanner.structure_processing(struct_provider.struct):
            # a keyword rule may be applicable for `key` (str only) and `value` (str, bytes)
            keyword_match = bool(isinstance(key, str) and self.scanner.keywords_required_substrings_check(key.lower()))

            if isinstance(value, (dict, list, tuple, frozenset, set)) and value:
                # recursive scan for not empty structured `value`
                val_struct_provider = StructContentProvider(struct=value,
                                                            file_path=struct_provider.file_path,
                                                            file_type=struct_provider.file_type,
                                                            info=f"{struct_provider.info}|STRUCT:{key}")
                new_candidates = self.structure_scan(val_struct_provider, depth, recursive_limit_size)
                candidates.extend(new_candidates)
            elif isinstance(value, (bytes, bytearray)):
                # recursive data scan
                if MIN_DATA_LEN <= len(value):
                    bytes_struct_provider = DataContentProvider(
                        data=bytes(value) if isinstance(value, bytearray) else value,
                        file_path=struct_provider.file_path,
                        file_type=struct_provider.file_type,
                        info=f"{struct_provider.info}|{'BYTEARRAY' if isinstance(value, bytearray) else 'BYTES'}:{key}")
                    new_candidates = self.recursive_scan(bytes_struct_provider, depth, recursive_limit_size)
                    candidates.extend(new_candidates)
                if keyword_match and MIN_VALUE_LENGTH <= len(value):
                    augmented_lines_for_keyword_rules.append(f"{key} = {repr(value)}")
            elif isinstance(value, str):
                # recursive text scan with transformation into bytes
                stripped_value = value.strip()
                if MIN_DATA_LEN <= len(stripped_value):
                    # recursive scan only for data which may be decoded at least
                    with contextlib.suppress(UnicodeError):
                        data = stripped_value.encode(encoding=DEFAULT_ENCODING, errors='strict')
                        str_struct_provider = DataContentProvider(data=data,
                                                                  file_path=struct_provider.file_path,
                                                                  file_type=struct_provider.file_type,
                                                                  info=f"{struct_provider.info}|STRING:{key}")
                        new_candidates = self.recursive_scan(str_struct_provider, depth, recursive_limit_size)
                        candidates.extend(new_candidates)
                if keyword_match and MIN_VALUE_LENGTH <= len(stripped_value):
                    augmented_lines_for_keyword_rules.append(f"{key} = {repr(stripped_value)}")
            elif not value or isinstance(value,
                                         (int, float, complex, slice, EllipsisType, datetime.date, datetime.datetime)):
                # skip useless types
                pass
            else:
                logger.warning("Not supported type:%s value(%s)", str(type(value)), str(value))

        if augmented_lines_for_keyword_rules:
            str_provider = StringContentProvider(augmented_lines_for_keyword_rules,
                                                 file_path=struct_provider.file_path,
                                                 file_type=struct_provider.file_type,
                                                 info=f"{struct_provider.info}|KEYWORD")
            new_candidates = self.scanner.scan(str_provider)
            augment_candidates(candidates, new_candidates)

        return candidates

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def deep_scan_with_fallback(self, data_provider: DataContentProvider, depth: int,
                                recursive_limit_size: int) -> List[Candidate]:
        """Scans with deep scanners and fallback scanners if possible

            Args:
                data_provider: DataContentProvider with raw data
                depth: maximal level of recursion
                recursive_limit_size: maximal bytes of opened files to prevent recursive zip-bomb attack

            Returns: list with candidates

        """
        candidates: List[Candidate] = []
        deep_scanners, fallback_scanners = self.get_deep_scanners(data_provider.data, data_provider.descriptor, depth,
                                                                  recursive_limit_size)
        fallback = True
        for scan_class in deep_scanners:
            new_candidates = scan_class.data_scan(self, data_provider, depth, recursive_limit_size)
            if new_candidates is None:
                # scanner did not recognise the content type
                continue
            augment_candidates(candidates, new_candidates)
            # this scan is successful, so fallback is not necessary
            fallback = False
        if fallback:
            for scan_class in fallback_scanners:
                fallback_candidates = scan_class.data_scan(self, data_provider, depth, recursive_limit_size)
                if fallback_candidates is None:
                    continue
                augment_candidates(candidates, fallback_candidates)
                # use only first successful fallback scanner
                break
        return candidates

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def scan(self,
             content_provider: ContentProvider,
             depth: int,
             recursive_limit_size: Optional[int] = None) -> List[Candidate]:
        """Initial scan method to launch recursive scan. Skips ByteScanner to prevent extra scan

            Args:
                content_provider: ContentProvider that might contain raw data
                depth: maximal level of recursion
                recursive_limit_size: maximal bytes of opened files to prevent recursive zip-bomb attack
        """
        if not isinstance(recursive_limit_size, int):
            recursive_limit_size = RECURSIVE_SCAN_LIMITATION
        candidates: List[Candidate] = []
        data: Optional[bytes] = None
        if isinstance(content_provider, (TextContentProvider, ByteContentProvider)):
            # Feature to scan files which might be containers
            data = content_provider.data
            info = f"FILE:{content_provider.file_path}"
        elif isinstance(content_provider, DiffContentProvider) and content_provider.diff:
            candidates = self.scanner.scan(content_provider)
            # Feature to scan binary diffs
            diff = content_provider.diff[0].get("line")
            # the check for legal fix mypy issue
            if isinstance(diff, bytes):
                data = diff
            info = f"DIFF:{content_provider.file_path}"
        else:
            logger.warning("Content provider %s does not support deep scan", type(content_provider))
            info = "NA"

        if data:
            data_provider = DataContentProvider(data=data,
                                                file_path=content_provider.file_path,
                                                file_type=Util.get_type(content_provider.file_path),
                                                info=content_provider.info or info)
            new_candidates = self.deep_scan_with_fallback(data_provider, depth, recursive_limit_size - len(data))
            augment_candidates(candidates, new_candidates)
        return candidates

    class LimitError(Exception):
        """Decompressed data exceeds configured limit"""

    @staticmethod
    def read_compressed_with_limit(file: Union[LZMAFile, GzipFile, BZ2File], limit: int) -> bytes:
        """Reads data with check limit for single compressed file"""
        size = file.seek(0, io.SEEK_END)
        if limit < size:
            raise AbstractScanner.LimitError(f"Recursive size limit reached {limit} < {size}")
        file.seek(0, io.SEEK_SET)
        return file.read(size=limit)
