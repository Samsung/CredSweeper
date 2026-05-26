import logging
import re
from typing import List, Any, Tuple, Union, Dict

from credsweeper.common.constants import MIN_DATA_LEN
from credsweeper.config.config import Config
from credsweeper.deep_scanner.byte_scanner import ByteScanner
from credsweeper.deep_scanner.bzip2_scanner import Bzip2Scanner
from credsweeper.deep_scanner.crx_scanner import CrxScanner
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
from credsweeper.deep_scanner.protobuf_scanner import ProtobufScanner
from credsweeper.deep_scanner.rpm_scanner import RpmScanner
from credsweeper.deep_scanner.rtf_scanner import RtfScanner
from credsweeper.deep_scanner.sqlite3_scanner import Sqlite3Scanner
from credsweeper.deep_scanner.strings_scanner import StringsScanner
from credsweeper.deep_scanner.tar_scanner import TarScanner
from credsweeper.deep_scanner.tmx_scanner import TmxScanner
from credsweeper.deep_scanner.xlsx_scanner import XlsxScanner
from credsweeper.deep_scanner.xml_scanner import XmlScanner
from credsweeper.deep_scanner.zip_scanner import ZipScanner
from credsweeper.deep_scanner.zlib_scanner import ZlibScanner
from credsweeper.file_handler.descriptor import Descriptor
from credsweeper.scanner.scanner import Scanner
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class DeepScanner(
    ByteScanner,  #
    Bzip2Scanner,  #
    CrxScanner,  #
    CsvScanner,  #
    DocxScanner,  #
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
    ProtobufScanner,  #
    RtfScanner,  #
    RpmScanner,  #
    Sqlite3Scanner,  #
    StringsScanner,  #
    TarScanner,  #
    DebScanner,  #
    XmlScanner,  #
    XlsxScanner,  #
    ZipScanner,  #
    ZlibScanner,  #
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

    # manually crafted dict to detect a media format with first byte, prefix and optionally pattern
    MEDIA_PATTERNS: Dict[int, List[Tuple[bytes, re.Pattern]]] = {
        0x00: [
            # JPEG2000
            (b"\x00\x00\x00\x0C\x6A\x50\x20\x20\x0D\x0A\x87\x0A", None),
            # ICO
            (b"\x00\x00\x01\x00", None),
            # TTF
            (b"\x00\x01\x00\x00\x00", None),
            # 3gp
            (b"\x00\x00\x00", re.compile(b"\x00\x00\x00.ftyp3g")),
            # GITCRYPT is not a media but added to use pedantic scan for strings and reduce extra warnings
            (b"\x00GITCRYPT\x00", None),
        ],
        0x1A: [
            # Matroska
            (b"\x1A\x45\xDF\xA3", None),
        ],
        0x7F: [
            # ELF signature - to quick pass for strings scanner
            (b"\x7FELF", re.compile(b"\x7FELF[\x01\x02][\x01\x02]\x01[\x00-\x12]"))
        ],
        0x89: [
            # PNG - can store text chunks inside
            (b"\x89PNG\x0D\x0A\x1A\x0A", None),
        ],
        0xFF: [
            # JPEG or MPEG-1 Layer 3
            (b"\xFF", re.compile(b"\xFF(\xD8\xFF[\xDB\xEE\xE1\xE0\x51]|[\xFB\xF3\xF2])")),
        ],
        ord('8'): [
            # PSD
            (b"8BPS\x00\x01\x00\x00\x00\x00\x00\x00", None),
            # PSB
            (b"8BPS\x00\x02\x00\x00\x00\x00\x00\x00", None),
        ],
        ord('B'): [
            # BMP
            (b"BM", re.compile(b"BM.{2}\x00{4}")),
        ],
        ord('G'): [
            # GIF
            (b"GIF8", re.compile(b"GIF8[79]a[^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")
             ),
        ],
        ord('I'): [
            # TIFF little endian
            (b"II", re.compile(b"II[+*]\x00[^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
            # ID2v3 for various media (e.g. MP3)
            (b"ID3\x03\x00\x00\x00", None),
        ],
        ord('M'): [
            # TIFF big endian
            (b"MM", re.compile(b"MM\x00[+*][^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
        ],
        ord('O'): [
            # OGG
            (b"OggS", re.compile(b"OggS[^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
            # OpenType font file
            (b"OTTO\x00",
             re.compile(b"OTTO\x00[^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
        ],
        ord('R'): [
            # RIFF va
            (b"RIF",
             re.compile(b"RIF[FX].{4}[ 0-9A-Za-z]{4}"
                        b"[^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
        ],
        ord('X'): [
            # Macromedia
            (b"XFIR",
             re.compile(b"XFIR.{4}[ 0-9A-Za-z]{4}"
                        b"[^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
        ],
        ord('f'): [
            # mp4
            (b"ftyp",
             re.compile(b"ftyp(isom|MSNV)[^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
        ],
        ord('g'): [
            # gimp
            (b"gimp xcf",
             re.compile(b"gimp xcf (file|v001|v002)\x00"
                        b"[^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
        ],
        ord('w'): [
            # WOFF 1.0, 2.0
            (b"wOF", re.compile(b"wOF[2F][^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
        ],
    }

    @staticmethod
    def is_media(data: Union[bytes, bytearray]) -> bool:
        """Returns True if well-known media format found"""
        if patterns := DeepScanner.MEDIA_PATTERNS.get(data[0]):
            for prefix, pattern in patterns:
                # use prefix for speed-up total search
                if prefix and data.startswith(prefix) and (pattern is None or pattern.match(data)):
                    return True
        return False

    @staticmethod
    def get_deep_scanners(data: bytes, descriptor: Descriptor, depth: int) -> Tuple[List[Any], List[Any]]:
        """Returns possibly scan methods for the data depends on content and fallback scanners"""
        deep_scanners: List[Any] = []
        fallback_scanners: List[Any] = []
        if not data or not isinstance(data, (bytes, bytearray)) or len(data) < MIN_DATA_LEN:
            # Guard clause: reject empty or invalid input data early
            pass
        elif ZipScanner.match(data):
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
        elif CrxScanner.match(data):
            if 0 < depth:
                deep_scanners.append(CrxScanner)
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
        elif DeepScanner.is_media(data):
            # only StringsScanner may be applied for the formats effective
            if 0 < depth:
                fallback_scanners.append(StringsScanner)
        elif not Util.is_binary(data):
            # keep ByteScanner first to apply real value position if possible
            deep_scanners.append(ByteScanner)
            if 0 < depth:
                deep_scanners.append(PatchScanner)
                deep_scanners.append(LangScanner)
                if CsvScanner.match(data):
                    deep_scanners.append(CsvScanner)
                if EncoderScanner.match(data):
                    deep_scanners.append(EncoderScanner)
                if ZlibScanner.match(data):
                    deep_scanners.append(ZlibScanner)
        else:
            if 0 < depth:
                if ZlibScanner.match(data):
                    deep_scanners.append(ZlibScanner)
                    fallback_scanners.append(StringsScanner)
                elif ProtobufScanner.match(data):
                    deep_scanners.append(ProtobufScanner)
                    fallback_scanners.append(StringsScanner)
                else:
                    deep_scanners.append(StringsScanner)
            if not descriptor.info.endswith("|BASE64"):
                logger.warning("Cannot apply a deep scanner for data(%d) %s %s", len(data), repr(data[:32]), descriptor)
        return deep_scanners, fallback_scanners
