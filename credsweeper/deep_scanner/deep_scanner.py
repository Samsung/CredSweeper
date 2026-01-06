import logging
from typing import List, Any, Tuple

from credsweeper.config.config import Config
from credsweeper.deep_scanner.byte_scanner import ByteScanner
from credsweeper.deep_scanner.bzip2_scanner import Bzip2Scanner
from credsweeper.deep_scanner.csv_scanner import CsvScanner
from credsweeper.deep_scanner.deb_scanner import DebScanner
from credsweeper.deep_scanner.docx_scanner import DocxScanner
from credsweeper.deep_scanner.eml_scanner import EmlScanner
from credsweeper.deep_scanner.encoder_scanner import EncoderScanner
from credsweeper.deep_scanner.gzip_scanner import GzipScanner
from credsweeper.deep_scanner.html_scanner import HtmlScanner
from credsweeper.deep_scanner.jclass_scanner import JclassScanner
from credsweeper.deep_scanner.jks_scanner import JksScanner
from credsweeper.deep_scanner.lang_scanner import LangScanner
from credsweeper.deep_scanner.lzma_scanner import LzmaScanner
from credsweeper.deep_scanner.mxfile_scanner import MxfileScanner
from credsweeper.deep_scanner.patch_scanner import PatchScanner
from credsweeper.deep_scanner.pdf_scanner import PdfScanner
from credsweeper.deep_scanner.pkcs_scanner import PkcsScanner
from credsweeper.deep_scanner.png_scanner import PngScanner
from credsweeper.deep_scanner.pptx_scanner import PptxScanner
from credsweeper.deep_scanner.rpm_scanner import RpmScanner
from credsweeper.deep_scanner.rtf_scanner import RtfScanner
from credsweeper.deep_scanner.sqlite3_scanner import Sqlite3Scanner
from credsweeper.deep_scanner.strings_scanner import StringsScanner
from credsweeper.deep_scanner.tar_scanner import TarScanner
from credsweeper.deep_scanner.tmx_scanner import TmxScanner
from credsweeper.deep_scanner.xlsx_scanner import XlsxScanner
from credsweeper.deep_scanner.xml_scanner import XmlScanner
from credsweeper.deep_scanner.zip_scanner import ZipScanner
from credsweeper.file_handler.descriptor import Descriptor
from credsweeper.scanner.scanner import Scanner
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class DeepScanner(
    ByteScanner,  #
    Bzip2Scanner,  #
    DocxScanner,  #
    CsvScanner,  #
    EncoderScanner,  #
    GzipScanner,  #
    HtmlScanner,  #
    JclassScanner,  #
    JksScanner,  #
    LangScanner,  #
    LzmaScanner,  #
    MxfileScanner,  #
    EmlScanner,  #
    PatchScanner,  #
    PdfScanner,  #
    PkcsScanner,  #
    PngScanner,  #
    PptxScanner,  #
    RtfScanner,  #
    RpmScanner,  #
    Sqlite3Scanner,  #
    StringsScanner,  #
    TarScanner,  #
    DebScanner,  #
    XmlScanner,  #
    XlsxScanner,  #
    ZipScanner,  #
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
    def get_deep_scanners(data: bytes, descriptor: Descriptor, depth: int) -> Tuple[List[Any], List[Any]]:
        """Returns possibly scan methods for the data depends on content and fallback scanners"""
        deep_scanners: List[Any] = []
        fallback_scanners: List[Any] = []
        if ZipScanner.match(data):
            if 0 < depth:
                deep_scanners.append(ZipScanner)
            # probably, there might be a docx, xlsx and so on.
            # It might be scanned with text representation in third-party libraries.
            if descriptor.extension in (".xlsx", ".ods"):
                deep_scanners.append(XlsxScanner)
            else:
                fallback_scanners.append(XlsxScanner)
            if ".docx" == descriptor.extension:
                deep_scanners.append(DocxScanner)
            else:
                fallback_scanners.append(DocxScanner)
            if ".pptx" == descriptor.extension:
                deep_scanners.append(PptxScanner)
            else:
                fallback_scanners.append(PptxScanner)
        elif XlsxScanner.match(data):
            if ".xls" == descriptor.extension:
                deep_scanners.append(XlsxScanner)
            else:
                fallback_scanners.append(XlsxScanner)
        elif Bzip2Scanner.match(data):
            if 0 < depth:
                deep_scanners.append(Bzip2Scanner)
        elif LzmaScanner.match(data):
            if 0 < depth:
                deep_scanners.append(LzmaScanner)
        elif TarScanner.match(data):
            if 0 < depth:
                deep_scanners.append(TarScanner)
        elif DebScanner.match(data):
            if 0 < depth:
                deep_scanners.append(DebScanner)
        elif GzipScanner.match(data):
            if 0 < depth:
                deep_scanners.append(GzipScanner)
        elif PdfScanner.match(data):
            deep_scanners.append(PdfScanner)
        elif PngScanner.match(data):
            deep_scanners.append(PngScanner)
        elif RpmScanner.match(data):
            if 0 < depth:
                deep_scanners.append(RpmScanner)
        elif JclassScanner.match(data):
            deep_scanners.append(JclassScanner)
        elif JksScanner.match(data):
            deep_scanners.append(JksScanner)
        elif Sqlite3Scanner.match(data):
            if 0 < depth:
                deep_scanners.append(Sqlite3Scanner)
        elif PkcsScanner.match(data):
            deep_scanners.append(PkcsScanner)
        elif RtfScanner.match(data):
            deep_scanners.append(RtfScanner)
            fallback_scanners.append(ByteScanner)
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
        elif not Util.is_binary(data):
            # keep ByteScanner first to apply real value position if possible
            deep_scanners.append(ByteScanner)
            if 0 < depth:
                deep_scanners.append(PatchScanner)
                deep_scanners.append(EncoderScanner)
                deep_scanners.append(LangScanner)
                deep_scanners.append(CsvScanner)
        else:
            if 0 < depth:
                deep_scanners.append(StringsScanner)
            else:
                logger.warning("Cannot apply a deep scanner for type %s prefix %s %d", descriptor, repr(data[:32]),
                               len(data))
        return deep_scanners, fallback_scanners
