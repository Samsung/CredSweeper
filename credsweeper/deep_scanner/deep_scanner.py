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
from credsweeper.deep_scanner.dex_scanner import DexScanner
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
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class DeepScanner(
    ByteScanner,  #
    Bzip2Scanner,  #
    CrxScanner,  #
    CsvScanner,  #
    DexScanner,  #
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

    # manually crafted dict to detect a media format with first byte, prefix and optionally pattern
    MEDIA_PATTERNS: Dict[int, List[Tuple[bytes, re.Pattern]]] = {
        0x00: [
            # JPEG2000
            (b"\x00\x00\x00\x0C\x6A\x50\x20\x20\x0D\x0A\x87\x0A", None),
            # ICO
            (b"\x00\x00\x01\x00", None),
            # CUR
            (b"\x00\x00\x02\x00\x01\x00", None),
            # TTF
            (b"\x00\x01\x00\x00\x00", None),
            # ftyp and some brands https://mp4ra.org/registered-types/brands
            (b"\x00\x00\x00",
             re.compile(b"\x00\x00\x00[\x00-\xFF]ftyp(3gp[4-9]|M4[ABPV] |qt  |iso[2-9abcm]|mp4[12]|hei[cmsx]|dash"
                        b"|avi[fos]|jx[ls] |mif[12]|avc[1-4]|ccff)")),
            # GITCRYPT is not a media but added to use pedantic scan for strings and reduce extra warnings
            (b"\x00GITCRYPT\x00", None),
            # binary web-assembly will be parsed like strings, however data section may be parsed too
            (b"\x00asm", None),
            # weird case
            (b"\x00\x00\xff\xff\x00\x00\x64\x86", None),
        ],
        0x03: [
            # Android Binary XML
            (b"\x03\x00\x08\x00", None),
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
            # HDF5
            (b"\x89HDF\r\n\x1a\n", None),
        ],
        0x93: [
            # NUMPY
            (b"\x93NUMPY", None),
        ],
        0xCE: [
            # Mach-O Executable (reverse 32 bit)
            (b"\xCE\xFA\xED\xFE", None),
        ],
        0xCF: [
            # Mach-O Executable (reverse 64 bit)
            (b"\xCF\xFA\xED\xFE", None),
        ],
        0xDE: [
            # GNU MO
            (b"\xDE\x12\x04\x95", None),
        ],
        0xFE: [
            # Mach-O Executable (32 bit)
            (b"\xFE\xED\xFA\xCE", None),
            # Mach-O Executable (64 bit)
            (b"\xFE\xED\xFA\xCF", None),
        ],
        0xFF: [
            # JPEG or MPEG-1 Layer 3
            (b"\xFF", re.compile(b"\xFF(\xD8\xFF[\xDB\xEE\xE1\xE0\x51]|[\xFB\xF3\xF2])")),
            # GIT: Version 2 pack-*.idx
            (b"\xFFtOc\x00\x00\x00", None),
        ],
        ord('8'): [
            # PSD
            (b"8BPS\x00\x01\x00\x00\x00\x00\x00\x00", None),
            # PSB
            (b"8BPS\x00\x02\x00\x00\x00\x00\x00\x00", None),
        ],
        ord('B'): [
            # BMP
            (b"BM", re.compile(b"BM[\x00-\xFF]{2}\x00{4}")),
            # netasm
            (b"BSJB\x01\x00\x01\x00\x00\x00\x00\x00", None),
        ],
        ord('G'): [
            # GIF
            (b"GIF8", re.compile(b"GIF8[79]a[^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")
             ),
        ],
        ord('I'): [
            # TIFF little endian
            (b"II", re.compile(b"II[+*]\x00[^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
            # jxr
            (b"II\xBC\x01", None),
            # ID2v3 for various media (e.g. MP3)
            (b"ID3", re.compile(b"ID3[\x02\x03]\x00\x00\x00")),
        ],
        ord('M'): [
            # TIFF big endian
            (b"MM", re.compile(b"MM\x00[+*][^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
            # EXE format with two zeroes bytes
            (b"MZ", re.compile(b"MZ[\x00-\xFF]{4,80}?\x00\x00")),
            # PDB
            (b"Microsoft C/C++ ",
             re.compile(b"Microsoft C/C[+][+] "
                        b"(program database 2[.]00\r\n\032JG\0\0|MSF 7[.]00\r\n\x1ADS\x00\x00\x00)")),
            # GIT: pack-*.mtimes
            (b"MTME\x00\x00\x00", None),
        ],
        ord('O'): [
            # OGG
            (b"OggS", re.compile(b"OggS[^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
            # OpenType font file
            (b"OTTO\x00",
             re.compile(b"OTTO\x00[^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
        ],
        ord('P'): [
            # GIT: pack-*.pack
            (b"PACK\x00\x00\x00", None),
        ],
        ord('R'): [
            # RIFF va
            (b"RIF",
             re.compile(b"RIF[FX][\x00-\xFF]{4}[ 0-9A-Za-z]{4}"
                        b"[^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
            # GIT: pack-*.rev
            (b"RIDX\x00\x00\x00", None)
        ],
        ord('T'): [
            # timezone info rfc9636
            (b"TZif", re.compile(b"TZif[\x00234]\x00{3}")),
        ],
        ord('X'): [
            # Macromedia
            (b"XFIR",
             re.compile(b"XFIR[\x00-\xFF]{4}[ 0-9A-Za-z]{4}"
                        b"[^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
        ],
        ord('f'): [
            # mp4
            (b"ftyp",
             re.compile(b"ftyp(isom|MSNV)[^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
            # FLAC magic number and seven used types https://www.rfc-editor.org/info/rfc9639/#metadata-block-header
            (b"fLaC", re.compile(b"fLaC[\x00-\x06]")),
        ],
        ord('g'): [
            # gimp
            (b"gimp xcf",
             re.compile(b"gimp xcf (file|v001|v002)\x00"
                        b"[^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
        ],
        ord('i'): [
            # icon image up to 24Mb
            (b"icns\x00",
             re.compile(b"icns\x00[\x00-\xFF]{3}"
                        b"(IC(ON|N#)|ic([hms][#48]|s[bB]|l[48]|p[456]|0[45789]|1[0-4])"
                        b"|is32|s8mk|il32|l8mk|ih32|h8mk|it32|t8mk|sb24|SB24)")),
        ],
        ord('w'): [
            # WOFF 1.0, 2.0
            (b"wOF", re.compile(b"wOF[2F][^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
        ],
        ord('x'): [
            # xar v1
            (b"xar!", re.compile(b"xar![\x00-\xFF]{2}\x00\x01")),
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
