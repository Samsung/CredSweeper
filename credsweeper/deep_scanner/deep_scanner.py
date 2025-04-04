import datetime
import logging
from typing import List, Optional, Any, Tuple, Union

from credsweeper.common.constants import RECURSIVE_SCAN_LIMITATION
from credsweeper.config import Config
from credsweeper.credentials import Candidate
from credsweeper.credentials.augment_candidates import augment_candidates
from credsweeper.file_handler.byte_content_provider import ByteContentProvider
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.diff_content_provider import DiffContentProvider
from credsweeper.file_handler.string_content_provider import StringContentProvider
from credsweeper.file_handler.text_content_provider import TextContentProvider
from credsweeper.scanner import Scanner
from credsweeper.utils import Util
from .byte_scanner import ByteScanner
from .bzip2_scanner import Bzip2Scanner
from .docx_scanner import DocxScanner
from .eml_scanner import EmlScanner
from .encoder_scanner import EncoderScanner
from .gzip_scanner import GzipScanner
from .html_scanner import HtmlScanner
from .jks_scanner import JksScanner
from .lang_scanner import LangScanner
from .mxfile_scanner import MxfileScanner
from .pdf_scanner import PdfScanner
from .pkcs12_scanner import Pkcs12Scanner
from .pptx_scanner import PptxScanner
from .tar_scanner import TarScanner
from .tmx_scanner import TmxScanner
from .xlsx_scanner import XlsxScanner
from .xml_scanner import XmlScanner
from .zip_scanner import ZipScanner
from ..common.constants import DEFAULT_ENCODING
from ..file_handler.file_path_extractor import FilePathExtractor
from ..file_handler.struct_content_provider import StructContentProvider

logger = logging.getLogger(__name__)


class DeepScanner(
    ByteScanner,  #
    Bzip2Scanner,  #
    DocxScanner,  #
    EncoderScanner,  #
    GzipScanner,  #
    HtmlScanner,  #
    JksScanner,  #
    LangScanner,  #
    PdfScanner,  #
    Pkcs12Scanner,  #
    PptxScanner,  #
    TarScanner,  #
    XmlScanner,  #
    XlsxScanner,  #
    ZipScanner
):  # yapf: disable
    """Advanced scanner with recursive exploring of data"""

    def __init__(self, config: Config, scanner: Scanner) -> None:
        """Initialize Advanced credential scanner.

        Args:
            scanner: CredSweeper scanner object
            config: dictionary variable, stores analyzer features
        """
        self.__config = config
        self.__scanner = scanner

    @property
    def config(self) -> Config:
        return self.__config

    @property
    def scanner(self) -> Scanner:
        return self.__scanner

    @staticmethod
    def get_deep_scanners(data: bytes, file_type: str, depth: int) -> Tuple[List[Any], List[Any]]:
        """Returns possibly scan methods for the data depends on content and fallback scanners"""
        deep_scanners: List[Any] = []
        fallback_scanners: List[Any] = []
        if Util.is_zip(data):
            if 0 < depth:
                deep_scanners.append(ZipScanner)
            # probably, there might be a docx, xlsx and so on.
            # It might be scanned with text representation in third-party libraries.
            if file_type in (".xlsx", ".ods"):
                deep_scanners.append(XlsxScanner)
            else:
                fallback_scanners.append(XlsxScanner)
            if ".docx" == file_type:
                deep_scanners.append(DocxScanner)
            else:
                fallback_scanners.append(DocxScanner)
            if ".pptx" == file_type:
                deep_scanners.append(PptxScanner)
            else:
                fallback_scanners.append(PptxScanner)
        elif Util.is_com(data):
            if ".xls" == file_type:
                deep_scanners.append(XlsxScanner)
            else:
                fallback_scanners.append(XlsxScanner)
        elif Util.is_bzip2(data):
            if 0 < depth:
                deep_scanners.append(Bzip2Scanner)
        elif Util.is_tar(data):
            if 0 < depth:
                deep_scanners.append(TarScanner)
        elif Util.is_gzip(data):
            if 0 < depth:
                deep_scanners.append(GzipScanner)
        elif Util.is_pdf(data):
            deep_scanners.append(PdfScanner)
        elif Util.is_jks(data):
            deep_scanners.append(JksScanner)
        elif Util.is_asn1(data):
            deep_scanners.append(Pkcs12Scanner)
        elif Util.is_xml(data):
            if Util.is_html(data):
                deep_scanners.append(HtmlScanner)
                deep_scanners.append(XmlScanner)
                fallback_scanners.append(ByteScanner)
            elif Util.is_mxfile(data):
                deep_scanners.append(MxfileScanner)
                deep_scanners.append(XmlScanner)
                fallback_scanners.append(ByteScanner)
            elif Util.is_tmx(data):
                deep_scanners.append(TmxScanner)
                fallback_scanners.append(XmlScanner)
                fallback_scanners.append(ByteScanner)
            else:
                deep_scanners.append(XmlScanner)
                fallback_scanners.append(ByteScanner)
        elif Util.is_eml(data):
            if ".eml" == file_type:
                deep_scanners.append(EmlScanner)
            else:
                fallback_scanners.append(EmlScanner)
            fallback_scanners.append(ByteScanner)
        elif not Util.is_binary(data):
            if 0 < depth:
                deep_scanners.append(EncoderScanner)
                deep_scanners.append(LangScanner)
            deep_scanners.append(ByteScanner)
        else:
            logger.warning("Cannot apply a deep scanner for type %s", file_type)
        return deep_scanners, fallback_scanners

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
        deep_scanners, fallback_scanners = self.get_deep_scanners(data_provider.data, data_provider.file_type, depth)
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
            for scan_class in deep_scanners:
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
        recursive_limit_size = recursive_limit_size if isinstance(recursive_limit_size,
                                                                  int) else RECURSIVE_SCAN_LIMITATION
        candidates: List[Candidate] = []
        data: Optional[bytes] = None
        if isinstance(content_provider, TextContentProvider) or isinstance(content_provider, ByteContentProvider):
            # Feature to scan files which might be containers
            data = content_provider.data
            info = "FILE"
        elif isinstance(content_provider, DiffContentProvider) and content_provider.diff:
            candidates = self.scanner.scan(content_provider)
            # Feature to scan binary diffs
            diff = content_provider.diff[0].get("line")
            # the check for legal fix mypy issue
            if isinstance(diff, bytes):
                data = diff
            info = "DIFF"
        else:
            logger.warning(f"Content provider {type(content_provider)} does not support deep scan")
            info = "NA"

        if data:
            data_provider = DataContentProvider(data=data,
                                                file_path=content_provider.file_path,
                                                file_type=content_provider.file_type,
                                                info=content_provider.info or info)
            new_candidates = self.deep_scan_with_fallback(data_provider, depth, recursive_limit_size - len(data))
            augment_candidates(candidates, new_candidates)
        return candidates

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
                                                            data_provider.file_type, data_provider.info,
                                                            FilePathExtractor.FIND_BY_EXT_RULE)
            candidates.append(dummy_candidate)
        else:
            new_candidates = self.deep_scan_with_fallback(data_provider, depth, recursive_limit_size)
            augment_candidates(candidates, new_candidates)

        return candidates

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

        if 0 > depth:
            # break recursion if maximal depth is reached
            logger.debug("bottom reached %s recursive_limit_size:%d", struct_provider.file_path, recursive_limit_size)
            return candidates

        depth -= 1

        items: List[Tuple[Union[int, str], Any]] = []
        struct_key: Optional[str] = None
        struct_value: Optional[str] = None
        line_for_keyword_rules = ""
        if isinstance(struct_provider.struct, dict):
            for key, value in struct_provider.struct.items():
                if isinstance(value, (list, tuple)) and 1 == len(value):
                    # simplify some structures like YAML when single item in new line is a value
                    items.append((key, value[0]))
                else:
                    items.append((key, value))
            # for transformation {"key": "api_key", "value": "XXXXXXX"} -> {"api_key": "XXXXXXX"}
            struct_key = struct_provider.struct.get("key")
            struct_value = struct_provider.struct.get("value")
        elif isinstance(struct_provider.struct, list) or isinstance(struct_provider.struct, tuple):
            items = list(enumerate(struct_provider.struct))
        else:
            logger.error("Not supported type:%s val:%s", str(type(struct_provider.struct)), str(struct_provider.struct))

        for key, value in items:
            if isinstance(value, dict) or isinstance(value, (list, tuple)) and 1 < len(value):
                val_struct_provider = StructContentProvider(struct=value,
                                                            file_path=struct_provider.file_path,
                                                            file_type=struct_provider.file_type,
                                                            info=f"{struct_provider.info}|STRUCT:{key}")
                new_candidates = self.structure_scan(val_struct_provider, depth, recursive_limit_size)
                candidates.extend(new_candidates)

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

                # use key = "value" scan for common cases like in TOML
                if isinstance(key, str) and self.scanner.keywords_required_substrings_check(key):
                    line_for_keyword_rules += f"{key} = \"{value}\"; "

            elif isinstance(value, (int, float, datetime.date, datetime.datetime)):
                # use the fields only in case of matched keywords
                if isinstance(key, str) and self.scanner.keywords_required_substrings_check(key):
                    line_for_keyword_rules += f"{key} = \"{value}\"; "

            else:
                logger.warning("Not supported type:%s value(%s)", str(type(value)), str(value))

        if line_for_keyword_rules:
            str_provider = StringContentProvider([line_for_keyword_rules],
                                                 file_path=struct_provider.file_path,
                                                 file_type=".toml",
                                                 info=f"{struct_provider.info}|KEYWORD:`{line_for_keyword_rules}`")
            new_candidates = self.scanner.scan(str_provider)
            augment_candidates(candidates, new_candidates)

        # last check when dictionary is {"key": "api_key", "value": "XXXXXXX"} -> {"api_key": "XXXXXXX"}
        if isinstance(struct_key, str) and isinstance(struct_value, str):
            line_for_keyword_rules = f"{struct_key} = \"{struct_value}\""
            key_value_provider = StringContentProvider(
                [line_for_keyword_rules],
                file_path=struct_provider.file_path,
                file_type=".toml",
                info=f"{struct_provider.info}|KEY_VALUE:`{line_for_keyword_rules}`")
            new_candidates = self.scanner.scan(key_value_provider)
            augment_candidates(candidates, new_candidates)
        return candidates
