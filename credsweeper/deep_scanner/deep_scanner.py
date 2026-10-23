import logging
from typing import List, Any, Tuple, Sequence

from credsweeper.common.constants import MIN_DATA_LEN
from credsweeper.config.config import Config
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.deep_scanner.bzip2_scanner import Bzip2Scanner
from credsweeper.deep_scanner.cpio_scanner import CpioScanner
from credsweeper.deep_scanner.crx_scanner import CrxScanner
from credsweeper.deep_scanner.csv_scanner import CsvScanner
from credsweeper.deep_scanner.deb_scanner import DebScanner
from credsweeper.deep_scanner.dex_scanner import DexScanner
from credsweeper.deep_scanner.docx_scanner import DocxScanner
from credsweeper.deep_scanner.eml_scanner import EmlScanner
from credsweeper.deep_scanner.encoder_scanner import EncoderScanner
from credsweeper.deep_scanner.grit_scanner import GritScanner
from credsweeper.deep_scanner.gzip_scanner import GzipScanner
from credsweeper.deep_scanner.html_scanner import HtmlScanner
from credsweeper.deep_scanner.jclass_scanner import JclassScanner
from credsweeper.deep_scanner.jks_scanner import JksScanner
from credsweeper.deep_scanner.lang_scanner import LangScanner
from credsweeper.deep_scanner.lexer_scanner import LexerScanner
from credsweeper.deep_scanner.lzma_scanner import LzmaScanner
from credsweeper.deep_scanner.mxfile_scanner import MxfileScanner
from credsweeper.deep_scanner.ods_scanner import OdsScanner
from credsweeper.deep_scanner.pandas_scanner import PandasScanner
from credsweeper.deep_scanner.patch_scanner import PatchScanner
from credsweeper.deep_scanner.pdf_scanner import PdfScanner
from credsweeper.deep_scanner.pickle_scanner import PickleScanner
from credsweeper.deep_scanner.pkcs_scanner import PkcsScanner
from credsweeper.deep_scanner.plist_scanner import PlistScanner
from credsweeper.deep_scanner.png_scanner import PngScanner
from credsweeper.deep_scanner.pptx_scanner import PptxScanner
from credsweeper.deep_scanner.protobuf_scanner import ProtobufScanner
from credsweeper.deep_scanner.pycache_scanner import PycacheScanner
from credsweeper.deep_scanner.rpm_scanner import RpmScanner
from credsweeper.deep_scanner.rtf_scanner import RtfScanner
from credsweeper.deep_scanner.snk_scanner import SnkScanner
from credsweeper.deep_scanner.sqlite3_scanner import Sqlite3Scanner
from credsweeper.deep_scanner.squashfs_scanner import SquashfsScanner
from credsweeper.deep_scanner.strings_scanner import StringsScanner
from credsweeper.deep_scanner.tar_scanner import TarScanner
from credsweeper.deep_scanner.text_scanner import TextScanner
from credsweeper.deep_scanner.tmx_scanner import TmxScanner
from credsweeper.deep_scanner.toml_scanner import TomlScanner
from credsweeper.deep_scanner.xls_scanner import XlsScanner
from credsweeper.deep_scanner.xlsx_scanner import XlsxScanner
from credsweeper.deep_scanner.xml_scanner import XmlScanner
from credsweeper.deep_scanner.yaml_scanner import YamlScanner
from credsweeper.deep_scanner.zip_scanner import ZipScanner
from credsweeper.deep_scanner.zlib_scanner import ZlibScanner
from credsweeper.deep_scanner.zstd_scanner import ZstdScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.scanner.scanner import Scanner
from credsweeper.utils.magic_detector import MagicDetector
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class DeepScanner(
    Bzip2Scanner,  #
    CpioScanner,  #
    CrxScanner,  #
    CsvScanner,  #
    DexScanner,  #
    DocxScanner,  #
    EncoderScanner,  #
    GritScanner,  #
    GzipScanner,  #
    HtmlScanner,  #
    JclassScanner,  #
    JksScanner,  #
    LangScanner,  #
    LexerScanner,  #
    LzmaScanner,  #
    MxfileScanner,  #
    EmlScanner,  #
    OdsScanner,  #
    PatchScanner,  #
    PdfScanner,  #
    PickleScanner,  #
    PkcsScanner,  #
    PlistScanner,  #
    PngScanner,  #
    PptxScanner,  #
    ProtobufScanner,  #
    PycacheScanner,  #
    RtfScanner,  #
    RpmScanner,  #
    SquashfsScanner,  #
    Sqlite3Scanner,  #
    SnkScanner,  #
    StringsScanner,  #
    TarScanner,  #
    TextScanner,  #
    TomlScanner,  #
    DebScanner,  #
    XmlScanner,  #
    XlsScanner,  #
    XlsxScanner,  #
    YamlScanner,  #
    ZipScanner,  #
    ZlibScanner,  #
    ZstdScanner,  #
):  # yapf: disable
    """Advanced scanner with recursive exploring of data"""

    BINARY_SCANNERS = (JksScanner, PdfScanner, SnkScanner, Sqlite3Scanner, CrxScanner, Bzip2Scanner, LzmaScanner,
                       GzipScanner, ZstdScanner, SquashfsScanner, GritScanner, DebScanner, RpmScanner, PngScanner,
                       JclassScanner, PkcsScanner, XlsScanner, TarScanner, PickleScanner, DexScanner, PlistScanner,
                       RtfScanner, PycacheScanner, CpioScanner)

    shelf = None

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
    def get_matched_scanner(
            data: bytes,  #
            scanner_classes: Sequence[type[AbstractScanner]],  #
    ) -> type[AbstractScanner] | None:
        """Returns matched scanner or None"""
        for scanner_class in scanner_classes:
            if scanner_class.match(data):
                return scanner_class
        return None

    @staticmethod
    def get_deep_scanners(data_provider: DataContentProvider, depth: int, limit: int) -> Tuple[List[Any], List[Any]]:
        """Returns possibly scan methods for the data depends on content and fallback scanners"""
        deep_scanners: List[Any] = []
        fallback_scanners: List[Any] = []
        data = data_provider.data
        if not data or not isinstance(data, (bytes, bytearray)) or len(data) < MIN_DATA_LEN:
            # Guard clause: reject empty or invalid input data early
            return deep_scanners, fallback_scanners
        if binary_scanner := DeepScanner.get_matched_scanner(data, DeepScanner.BINARY_SCANNERS):
            # binary scanner detection
            if 0 < depth or binary_scanner.shelf:
                deep_scanners.append(binary_scanner)
            else:
                deep_scanners.append(StringsScanner)
        elif ZipScanner.match(data):
            # zip matched but may be not scanned due limit exhausted
            if 0 < ZipScanner.get_size(data) < limit:
                if 0 < depth:
                    deep_scanners.append(ZipScanner)
                # probably, there might be a docx, xlsx and so on.
                # It might be scanned with text representation in third-party libraries.
                if b"[Content_Types].xml" in data and b"_rels/.rels" in data:
                    if XlsxScanner.match(data):
                        deep_scanners.append(PandasScanner)
                    if DocxScanner.match(data):
                        deep_scanners.append(DocxScanner)
                    if PptxScanner.match(data):
                        deep_scanners.append(PptxScanner)
                if OdsScanner.match(data):
                    deep_scanners.append(PandasScanner)
        elif XmlScanner.match(data) and data_provider.text:
            if HtmlScanner.match(data):
                deep_scanners.append(HtmlScanner)
                deep_scanners.append(XmlScanner)
            elif MxfileScanner.match(data):
                deep_scanners.append(MxfileScanner)
                deep_scanners.append(XmlScanner)
            elif TmxScanner.match(data):
                deep_scanners.append(TmxScanner)
                fallback_scanners.append(XmlScanner)
            else:
                deep_scanners.append(XmlScanner)
            fallback_scanners.append(TextScanner)
        elif EmlScanner.match(data):
            if data_provider.descriptor.extension in (".eml", ".mht"):
                deep_scanners.append(EmlScanner)
            else:
                if 0 < depth and PatchScanner.match(data):
                    # a formal patch looks like an eml
                    deep_scanners.append(PatchScanner)
                fallback_scanners.append(EmlScanner)
            if data_provider.text:
                fallback_scanners.append(TextScanner)
        elif MagicDetector.detect(data):
            # only StringsScanner may be applied for the formats effective
            fallback_scanners.append(StringsScanner)
        elif not Util.is_binary(data):
            # keep TextScanner first to apply real value position if possible
            deep_scanners.append(TextScanner)
            if 0 < depth:
                if PatchScanner.match(data):
                    deep_scanners.append(PatchScanner)
                if ZlibScanner.match(data):
                    deep_scanners.append(ZlibScanner)
                if data_provider.text:
                    # data provider data can be transformed to text
                    if LangScanner.match(data):
                        deep_scanners.append(LangScanner)
                    if LexerScanner.match(data):
                        deep_scanners.append(LexerScanner)
                    if TomlScanner.match(data):
                        deep_scanners.append(TomlScanner)
                    if CsvScanner.match(data):
                        deep_scanners.append(CsvScanner)
                    if EncoderScanner.match(data):
                        deep_scanners.append(EncoderScanner)
                    if YamlScanner.match(data):
                        deep_scanners.append(YamlScanner)
        else:
            unknown_warning = not (data_provider.descriptor.info.endswith("|BASE64")
                                   or "|PROTO:" in data_provider.descriptor.info)
            if 0 < depth:
                if ZlibScanner.match(data):
                    deep_scanners.append(ZlibScanner)
                    unknown_warning = False
                elif ProtobufScanner.match(data):
                    deep_scanners.append(ProtobufScanner)
                    unknown_warning = False
                else:
                    deep_scanners.append(StringsScanner)
            if unknown_warning:
                logger.debug("Cannot apply a deep scanner for data(%d) %s %s", len(data), repr(data[:32]),
                             data_provider.descriptor)
        # set StringsScanner as fallback if not assigned for regular scanners
        if not fallback_scanners and StringsScanner not in deep_scanners and TextScanner not in deep_scanners:
            fallback_scanners.append(StringsScanner)
        return deep_scanners, fallback_scanners
