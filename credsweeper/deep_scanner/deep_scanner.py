import logging
from typing import List, Any, Tuple

from credsweeper.config.config import Config
from credsweeper.scanner.scanner import Scanner
from credsweeper.utils.util import Util
from .byte_scanner import ByteScanner
from .bzip2_scanner import Bzip2Scanner
from .csv_scanner import CsvScanner
from .deb_scanner import DebScanner
from .docx_scanner import DocxScanner
from .eml_scanner import EmlScanner
from .encoder_scanner import EncoderScanner
from .gzip_scanner import GzipScanner
from .html_scanner import HtmlScanner
from .jclass_scanner import JclassScanner
from .jks_scanner import JksScanner
from .lang_scanner import LangScanner
from .lzma_scanner import LzmaScanner
from .mxfile_scanner import MxfileScanner
from .patch_scanner import PatchScanner
from .pdf_scanner import PdfScanner
from .pkcs_scanner import PkcsScanner
from .pptx_scanner import PptxScanner
from .rpm_scanner import RpmScanner
from .rtf_scanner import RtfScanner
from .sqlite3_scanner import Sqlite3Scanner
from .strings_scanner import StringsScanner
from .tar_scanner import TarScanner
from .tmx_scanner import TmxScanner
from .xlsx_scanner import XlsxScanner
from .xml_scanner import XmlScanner
from .zip_scanner import ZipScanner
from ..file_handler.descriptor import Descriptor

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
    PatchScanner,  #
    PdfScanner,  #
    PkcsScanner,  #
    PptxScanner,  #
    RtfScanner,  #
    RpmScanner,  #
    Sqlite3Scanner,  #
    StringsScanner,  #
    TarScanner,  #
    DebScanner,  #
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
    def get_deep_scanners(data: bytes, descriptor: Descriptor, depth: int) -> Tuple[List[Any], List[Any]]:
        """Returns possibly scan methods for the data depends on content and fallback scanners"""
        deep_scanners: List[Any] = []
        fallback_scanners: List[Any] = []
        if Util.is_zip(data):
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
        elif Util.is_com(data):
            if ".xls" == descriptor.extension:
                deep_scanners.append(XlsxScanner)
            else:
                fallback_scanners.append(XlsxScanner)
        elif Util.is_bzip2(data):
            if 0 < depth:
                deep_scanners.append(Bzip2Scanner)
        elif Util.is_lzma(data):
            if 0 < depth:
                deep_scanners.append(LzmaScanner)
        elif Util.is_tar(data):
            if 0 < depth:
                deep_scanners.append(TarScanner)
        elif Util.is_deb(data):
            if 0 < depth:
                deep_scanners.append(DebScanner)
        elif Util.is_gzip(data):
            if 0 < depth:
                deep_scanners.append(GzipScanner)
        elif Util.is_pdf(data):
            deep_scanners.append(PdfScanner)
        elif Util.is_rpm(data):
            if 0 < depth:
                deep_scanners.append(RpmScanner)
        elif Util.is_jclass(data):
            deep_scanners.append(JclassScanner)
        elif Util.is_jks(data):
            deep_scanners.append(JksScanner)
        elif Util.is_sqlite3(data):
            if 0 < depth:
                deep_scanners.append(Sqlite3Scanner)
        elif Util.is_asn1(data):
            deep_scanners.append(PkcsScanner)
        elif Util.is_rtf(data):
            deep_scanners.append(RtfScanner)
            fallback_scanners.append(ByteScanner)
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
