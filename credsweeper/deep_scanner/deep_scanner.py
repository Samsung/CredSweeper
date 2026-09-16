import logging
from typing import List, Any, Tuple

from credsweeper.common.constants import MIN_DATA_LEN
from credsweeper.config.config import Config
from credsweeper.deep_scanner.byte_scanner import ByteScanner
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
from credsweeper.deep_scanner.tmx_scanner import TmxScanner
from credsweeper.deep_scanner.xls_scanner import XlsScanner
from credsweeper.deep_scanner.xlsx_scanner import XlsxScanner
from credsweeper.deep_scanner.xml_scanner import XmlScanner
from credsweeper.deep_scanner.zip_scanner import ZipScanner
from credsweeper.deep_scanner.zlib_scanner import ZlibScanner
from credsweeper.deep_scanner.zstd_scanner import ZstdScanner
from credsweeper.file_handler.descriptor import Descriptor
from credsweeper.scanner.scanner import Scanner
from credsweeper.utils.magic_detector import MagicDetector
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class DeepScanner(
    ByteScanner,  #
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
    DebScanner,  #
    XmlScanner,  #
    XlsScanner,  #
    XlsxScanner,  #
    ZipScanner,  #
    ZlibScanner,  #
    ZstdScanner,  #
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
    def get_deep_scanners(data: bytes, descriptor: Descriptor, depth: int, limit: int) -> Tuple[List[Any], List[Any]]:
        """Returns possibly scan methods for the data depends on content and fallback scanners"""
        deep_scanners: List[Any] = []
        fallback_scanners: List[Any] = []
        if not data or not isinstance(data, (bytes, bytearray)) or len(data) < MIN_DATA_LEN:
            # Guard clause: reject empty or invalid input data early
            pass
        elif PdfScanner.match(data):
            deep_scanners.append(PdfScanner)
        elif PngScanner.match(data):
            deep_scanners.append(PngScanner)
        elif JclassScanner.match(data):
            deep_scanners.append(JclassScanner)
        elif JksScanner.match(data):
            deep_scanners.append(JksScanner)
        elif SnkScanner.match(data):
            deep_scanners.append(SnkScanner)
        elif Sqlite3Scanner.match(data):
            if 0 < depth:
                deep_scanners.append(Sqlite3Scanner)
        elif PkcsScanner.match(data):
            deep_scanners.append(PkcsScanner)
        elif XlsScanner.match(data):
            deep_scanners.append(PandasScanner)
        elif CrxScanner.match(data):
            if 0 < depth:
                deep_scanners.append(CrxScanner)
        elif Bzip2Scanner.match(data):
            if 0 < depth:
                deep_scanners.append(Bzip2Scanner)
        elif LzmaScanner.match(data):
            if 0 < depth:
                deep_scanners.append(LzmaScanner)
        elif GzipScanner.match(data):
            if 0 < depth:
                deep_scanners.append(GzipScanner)
        elif ZstdScanner.match(data):
            if 0 < depth:
                deep_scanners.append(ZstdScanner)
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
        elif SquashfsScanner.match(data):
            if 0 < depth:
                deep_scanners.append(SquashfsScanner)
        elif GritScanner.match(data):
            if 0 < depth:
                deep_scanners.append(GritScanner)
        elif DebScanner.match(data):
            if 0 < depth:
                deep_scanners.append(DebScanner)
        elif TarScanner.match(data):
            if 0 < depth:
                deep_scanners.append(TarScanner)
                fallback_scanners.append(StringsScanner)
        elif RpmScanner.match(data):
            if 0 < depth:
                deep_scanners.append(RpmScanner)
        elif PickleScanner.match(data):
            if 0 < depth:
                deep_scanners.append(PickleScanner)
                fallback_scanners.append(StringsScanner)
        elif DexScanner.match(data):
            if 0 < depth:
                deep_scanners.append(DexScanner)
                fallback_scanners.append(StringsScanner)
        elif PlistScanner.match(data):
            if 0 < depth:
                deep_scanners.append(PlistScanner)
                fallback_scanners.append(StringsScanner)
        elif PycacheScanner.match(data):
            if 0 < depth:
                deep_scanners.append(PycacheScanner)
                fallback_scanners.append(StringsScanner)
        elif RtfScanner.match(data):
            deep_scanners.append(RtfScanner)
            fallback_scanners.append(StringsScanner)
        elif CpioScanner.match(data):
            logger.info('match')
            deep_scanners.append(CpioScanner)
            fallback_scanners.append(StringsScanner)
        elif XmlScanner.match(data):
            if HtmlScanner.match(data):
                deep_scanners.append(HtmlScanner)
                deep_scanners.append(XmlScanner)
                fallback_scanners.append(ByteScanner)
            elif MxfileScanner.match(data):
                deep_scanners.append(MxfileScanner)
                deep_scanners.append(XmlScanner)
                fallback_scanners.append(ByteScanner)
            elif TmxScanner.match(data):
                deep_scanners.append(TmxScanner)
                fallback_scanners.append(XmlScanner)
                fallback_scanners.append(ByteScanner)
            else:
                deep_scanners.append(XmlScanner)
                fallback_scanners.append(ByteScanner)
        elif EmlScanner.match(data):
            if descriptor.extension in (".eml", ".mht"):
                deep_scanners.append(EmlScanner)
            else:
                if 0 < depth:
                    # a formal patch looks like an eml
                    deep_scanners.append(PatchScanner)
                fallback_scanners.append(EmlScanner)
            fallback_scanners.append(ByteScanner)
        elif MagicDetector.detect(data):
            # only StringsScanner may be applied for the formats effective
            if 0 < depth:
                fallback_scanners.append(StringsScanner)
        elif not Util.is_binary(data):
            # keep ByteScanner first to apply real value position if possible
            deep_scanners.append(ByteScanner)
            if 0 < depth:
                deep_scanners.append(PatchScanner)
                deep_scanners.append(LangScanner)
                if LexerScanner.match(data):
                    deep_scanners.append(LexerScanner)
                if CsvScanner.match(data):
                    deep_scanners.append(CsvScanner)
                if EncoderScanner.match(data):
                    deep_scanners.append(EncoderScanner)
                if ZlibScanner.match(data):
                    deep_scanners.append(ZlibScanner)
        else:
            unknown_warning = not (descriptor.info.endswith("|BASE64") or "|PROTO:" in descriptor.info)
            if 0 < depth:
                if ZlibScanner.match(data):
                    deep_scanners.append(ZlibScanner)
                    fallback_scanners.append(StringsScanner)
                    unknown_warning = False
                elif ProtobufScanner.match(data):
                    deep_scanners.append(ProtobufScanner)
                    fallback_scanners.append(StringsScanner)
                    unknown_warning = False
                else:
                    deep_scanners.append(StringsScanner)
            if unknown_warning:
                logger.warning("Cannot apply a deep scanner for data(%d) %s %s", len(data), repr(data[:32]), descriptor)
        return deep_scanners, fallback_scanners
