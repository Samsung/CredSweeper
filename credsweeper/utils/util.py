import ast
import base64
import contextlib
import json
import logging
import math
import os
import random
import re
import string
import tarfile
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional, Union

import numpy as np
import yaml
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.dh import DHPrivateKey, DHPublicKey
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey, DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey, X448PrivateKey
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from lxml import etree

from credsweeper.common.constants import AVAILABLE_ENCODINGS, \
    DEFAULT_ENCODING, LATIN_1, CHUNK_SIZE, MAX_LINE_LENGTH, CHUNK_STEP_SIZE, ASCII

logger = logging.getLogger(__name__)


class Util:
    """Class that contains different useful methods."""

    @staticmethod
    def get_extension(file_path: str, lower=True) -> str:
        """Return extension of file in lower case by default e.g.: '.txt', '.JPG'"""
        _, extension = os.path.splitext(str(file_path))
        return extension.lower() if lower else extension

    @staticmethod
    def get_regex_combine_or(re_strs: List[str]) -> str:
        """Routine combination for regex 'or'"""
        result = "(?:"

        for elem in re_strs:
            result += elem + "|"

        if result[-1] == "|":
            result = result[:-1]
        result += ")"

        return result

    @staticmethod
    def get_shannon_entropy(data: Union[str, bytes]) -> float:
        """Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html."""
        if not data:
            return 0.0
        size = len(data)
        _uniq, counts = np.unique(list(data), return_counts=True)
        probabilities = counts / size
        entropy = -float(np.sum(probabilities * np.log2(probabilities)))
        return entropy

    # Precalculated data for speedup
    MIN_DATA_ENTROPY: Dict[int, float] = {
        16: 1.66973671780348,
        20: 2.07723544540831,
        32: 3.25392803184602,
        40: 3.64853567064867,
        64: 4.57756933688035,
        384: 7.39,
        512: 7.55,
    }

    @staticmethod
    def get_min_data_entropy(x: int) -> float:
        """Returns minimal entropy for size of random data. Precalculated data is applied for speedup"""
        if x in Util.MIN_DATA_ENTROPY:
            y = Util.MIN_DATA_ENTROPY[x]
        elif 8 < x < 64:
            # approximated for range 12 - 64
            _x = x - 8
            y = ((0.000016617804 * _x - 0.002695077) * _x + 0.170393) * _x + 0.4
        elif 64 < x < 384:
            # logarithm base 2 - slow, but precise
            _x = x - 8
            y = 1.095884 * math.log2(_x) - 1.90156
        elif 384 < x < 512:
            # solved for 384 - 512
            y = -0.11215851 * math.log2(x)**2 + 2.34303484 * math.log2(x) - 4.4466237
        else:
            # less or equal to 8 bytes might have 0 entropy
            y = 0
        return y

    @staticmethod
    def is_ascii_entropy_validate(data: bytes) -> bool:
        """
        Tests small data sequence (<256) for data randomness by testing for ascii and shannon entropy
        Returns True when data is an ASCII symbols or have small entropy
        """
        if not data:
            return True
        data_len = len(data)
        if 9 > data_len:
            # even random data may have 0 entropy for length of 8 bytes and less
            return True
        entropy = 0.
        cells = [int(0)] * 256
        ascii_test = True
        # "basket" sorting approach
        for x in data:
            cells[x] += 1
            if ascii_test and 0b10000000 & x:
                ascii_test = False
        if ascii_test:
            # only ascii symbols found
            return True
        left = 0.
        step = 256.0 / data_len
        right = left + step
        while left < 256:
            cell_sum = 0
            i = int(left)
            r = int(right)
            while i < r and i < 256:
                cell_sum += cells[i]
                i += 1
            p_x = float(cell_sum) / data_len
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
            left = right
            right += step
        min_entropy = Util.get_min_data_entropy(data_len)
        return entropy < min_entropy

    @staticmethod
    def is_binary(data: Union[bytes, bytearray]) -> bool:
        """
        Returns True when two zeroes sequence is found in begin of data.
        The sequence never exists in text format (UTF-8, UTF-16). UTF-32 is not supported.
        """
        if isinstance(data, (bytes, bytearray)) and 0 <= data.find(b"\0\0", 0, MAX_LINE_LENGTH):
            return True
        return False

    NOT_LATIN1_PRINTABLE_SET = set(range(0, 256)) \
        .difference(set(x for x in string.printable.encode(ASCII))) \
        .difference(set(x for x in range(0xA0, 0x100)))

    @staticmethod
    def is_latin1(data: Union[bytes, bytearray]) -> bool:
        """Returns True when data looks like LATIN-1 for first MAX_LINE_LENGTH bytes."""
        result = False
        if data:
            non_latin1_cnt = sum(1 for x in data[:MAX_LINE_LENGTH] if x in Util.NOT_LATIN1_PRINTABLE_SET)
            # experiment for 255217 binary files shown avg = 0.268264 ± 0.168767, so let choose minimal
            chunk_len = min(MAX_LINE_LENGTH, len(data))
            result = bool(0.1 > non_latin1_cnt / chunk_len)
        return result

    @staticmethod
    def read_file(path: Union[str, Path], encodings: Optional[List[str]] = None) -> List[str]:
        """Read the file content using different encodings.

        Try to read the contents of the file according to the list of encodings "encodings" as soon as reading
        occurs without any exceptions, the data is returned in the current encoding

        Args:
            path: path to file
            encodings: supported encodings

        Return:
            list of file rows in a suitable encoding from "encodings",
            if none of the encodings match, an empty list will be returned

        """
        data = Util.read_data(path)
        return Util.decode_bytes(data, encodings)

    @staticmethod
    def decode_text(content: bytes, encodings: Optional[List[str]] = None) -> Optional[str]:
        """Decode content using different encodings.

        Try to decode bytes according to the list of encodings "encodings"
        occurs without any exceptions. UTF-16 requires BOM

        Args:
            content: raw data that might be text
            encodings: supported encodings

        Return:
            Decoded text in str for any suitable encoding
            or None when binary data detected

        """
        text = None
        binary_suggest = False
        if encodings is None:
            encodings = AVAILABLE_ENCODINGS
        for encoding in encodings:
            try:
                if binary_suggest and LATIN_1 == encoding and (Util.is_binary(content) or not Util.is_latin1(content)):
                    # LATIN_1 may convert data (bytes in range 0x80:0xFF are transformed)
                    break
                _text = content.decode(encoding=encoding, errors="strict")
                if content != _text.encode(encoding=encoding, errors="strict"):
                    # the check helps to detect a real encoding
                    raise UnicodeError
                text = _text
                break
            except UnicodeError:
                binary_suggest = True
                logger.info(f"UnicodeError: Can't decode content as {encoding}.")
            except Exception as exc:
                logger.error(f"Unexpected Error: Can't read content as {encoding}. Error message: {exc}")
        return text

    @staticmethod
    def split_text(text: str) -> List[str]:
        """Splits a text into lines, handling all common line endings (e.g., LF, CRLF, CR)."""
        return text.replace("\r\n", '\n').replace('\r', '\n').split('\n')

    @staticmethod
    def decode_bytes(content: bytes, encodings: Optional[List[str]] = None) -> List[str]:
        """Decode content using different encodings.

        Try to decode bytes according to the list of encodings "encodings"
        occurs without any exceptions. UTF-16 requires BOM

        Args:
            content: raw data that might be text
            encodings: supported encodings

        Return:
            list of file rows in a suitable encoding from "encodings",
            if none of the encodings match, an empty list will be returned
            Also empty list will be returned after last encoding and 0 symbol is present in lines not at end

        """
        if text := Util.decode_text(content, encodings):
            lines = Util.split_text(text)
        else:
            lines = []
        return lines

    @staticmethod
    def is_zip(data: Union[bytes, bytearray]) -> bool:
        """According https://en.wikipedia.org/wiki/List_of_file_signatures"""
        if isinstance(data, (bytes, bytearray)) and data.startswith(b"PK") and 4 <= len(data):
            if 0x03 == data[2] and 0x04 == data[3]:
                # normal PK
                return True
            elif 0x05 == data[2] and 0x06 == data[3]:
                # empty archive - no sense to scan in other scanners, so let it be a zip
                return True
            elif 0x07 == data[2] and 0x08 == data[3]:
                # spanned archive - NOT SUPPORTED
                return False
        return False

    @staticmethod
    def is_com(data: Union[bytes, bytearray]) -> bool:
        """According https://en.wikipedia.org/wiki/List_of_file_signatures"""
        if isinstance(data, (bytes, bytearray)) and data.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
            # Compound File Binary Format: doc, xls, ppt, msi, msg
            return True
        return False

    @staticmethod
    def is_rpm(data: Union[bytes, bytearray]) -> bool:
        """According https://en.wikipedia.org/wiki/List_of_file_signatures"""
        if isinstance(data, (bytes, bytearray)) and data.startswith(b"\xED\xAB\xEE\xDB"):
            return True
        return False

    @staticmethod
    def is_tar(data: Union[bytes, bytearray]) -> bool:
        """According https://en.wikipedia.org/wiki/List_of_file_signatures"""
        if isinstance(data, (bytes, bytearray)) and 512 <= len(data):
            if 0x75 == data[257] and 0x73 == data[258] and 0x74 == data[259] \
                    and 0x61 == data[260] and 0x72 == data[261] and (
                    0x00 == data[262] and 0x30 == data[263] and 0x30 == data[264]
                    or
                    0x20 == data[262] and 0x20 == data[263] and 0x00 == data[264]
            ):
                with contextlib.suppress(Exception):
                    chksum = tarfile.nti(data[148:156])  # type: ignore
                    unsigned_chksum, signed_chksum = tarfile.calc_chksums(data)  # type: ignore
                    if chksum == unsigned_chksum or chksum == signed_chksum:
                        return True
        return False

    @staticmethod
    def is_deb(data: Union[bytes, bytearray]) -> bool:
        """According https://en.wikipedia.org/wiki/Deb_(file_format)"""
        if isinstance(data, (bytes, bytearray)) and data.startswith(b"!<arch>\n"):
            return True
        return False

    @staticmethod
    def is_bzip2(data: Union[bytes, bytearray]) -> bool:
        """According https://en.wikipedia.org/wiki/Bzip2"""
        if isinstance(data, (bytes, bytearray)) and data.startswith(b"\x42\x5A\x68") and 10 <= len(data) \
                and 0x31 <= data[3] <= 0x39 \
                and 0x31 == data[4] and 0x41 == data[5] and 0x59 == data[6] \
                and 0x26 == data[7] and 0x53 == data[8] and 0x59 == data[9]:
            return True
        return False

    @staticmethod
    def is_gzip(data: Union[bytes, bytearray]) -> bool:
        """According https://www.rfc-editor.org/rfc/rfc1952"""
        if isinstance(data, (bytes, bytearray)) and data.startswith(b"\x1F\x8B\x08"):
            return True
        return False

    @staticmethod
    def is_pdf(data: Union[bytes, bytearray]) -> bool:
        """According https://en.wikipedia.org/wiki/List_of_file_signatures - pdf"""
        if isinstance(data, (bytes, bytearray)) and data.startswith(b"%PDF-"):
            return True
        return False

    @staticmethod
    def is_jclass(data: Union[bytes, bytearray]) -> bool:
        """According https://en.wikipedia.org/wiki/List_of_file_signatures - java class"""
        if isinstance(data, (bytes, bytearray)) and data.startswith(b"\xCA\xFE\xBA\xBE"):
            return True
        return False

    @staticmethod
    def is_jks(data: Union[bytes, bytearray]) -> bool:
        """According https://en.wikipedia.org/wiki/List_of_file_signatures - jks"""
        if isinstance(data, (bytes, bytearray)) and data.startswith(b"\xFE\xED\xFE\xED"):
            return True
        return False

    @staticmethod
    def is_lzma(data: Union[bytes, bytearray]) -> bool:
        """According https://en.wikipedia.org/wiki/List_of_file_signatures - lzma also xz"""
        if isinstance(data, (bytes, bytearray)) and data.startswith((b"\xFD7zXZ\x00", b"\x5D\x00\x00")):
            return True
        return False

    @staticmethod
    def is_sqlite3(data: Union[bytes, bytearray]):
        """According https://en.wikipedia.org/wiki/List_of_file_signatures - SQLite Database"""
        if isinstance(data, (bytes, bytearray)) and data.startswith(b"SQLite format 3\0"):
            return True
        return False

    @staticmethod
    def is_rtf(data: Union[bytes, bytearray]):
        """According https://en.wikipedia.org/wiki/List_of_file_signatures - Rich Text Format"""
        if isinstance(data, (bytes, bytearray)) and data.startswith(b"{\\rtf1") and data.endswith(b"}"):
            return True
        return False

    @staticmethod
    def is_asn1(data: Union[bytes, bytearray]) -> int:
        """Only sequence type 0x30 and size correctness are checked
        Returns size of ASN1 data over 128 bytes or 0 if no interested data
        """
        if isinstance(data, (bytes, bytearray)) and 2 <= len(data) and 0x30 == data[0]:
            # https://www.oss.com/asn1/resources/asn1-made-simple/asn1-quick-reference/basic-encoding-rules.html#Lengths
            length = data[1]
            if 0x80 == length:
                if data.endswith(b"\x00\x00"):
                    # assume, all data are ASN1 of various size
                    return len(data)
                else:
                    # skip the case where the ASN1 size is smaller than the actual data
                    return 0
            elif 0x80 < length:
                byte_len = 0x7F & length
                len_limit = 2 + byte_len
                if 4 >= byte_len and len(data) >= len_limit:
                    length = 0
                    for i in range(2, len_limit):
                        length <<= 8
                        length |= data[i]
                    if len(data) >= length + len_limit:
                        return length + len_limit
                else:
                    # unsupported huge size
                    return 0
            else:
                # less than 0x80
                if len(data) >= length + 2:
                    return length + 2
        return 0

    @staticmethod
    def is_html(data: Union[bytes, bytearray]) -> bool:
        """Used to detect html format. Suppose, invocation of is_xml() was True before."""
        if isinstance(data, (bytes, bytearray)):
            for opening_tag, closing_tag in [(b"<html", b"</html>"), (b"<body", b"</body>"), (b"<table", b"</table>"),
                                             (b"<p>", b"</p>"), (b"<span>", b"</span>"), (b"<div>", b"</div>"),
                                             (b"<li>", b"</li>"), (b"<ol>", b"</ol>"), (b"<ul>", b"</ul>"),
                                             (b"<th>", b"</th>"), (b"<tr>", b"</tr>"), (b"<td>", b"</td>")]:
                opening_pos = data.find(opening_tag, 0, MAX_LINE_LENGTH)
                if 0 <= opening_pos < data.find(closing_tag, opening_pos):
                    # opening and closing tags were found - suppose it is an HTML
                    return True
        return False

    @staticmethod
    def is_mxfile(data: Union[bytes, bytearray]) -> bool:
        """Used to detect mxfile (drawio) format. Suppose, invocation of is_xml() was True before."""
        if isinstance(data, (bytes, bytearray)):
            mxfile_tag_pos = data.find(b"<mxfile", 0, MAX_LINE_LENGTH)
            if 0 <= mxfile_tag_pos < data.find(b"</mxfile>", mxfile_tag_pos):
                return True
        return False

    @staticmethod
    def is_tmx(data: Union[bytes, bytearray]) -> bool:
        """Used to detect tm7,tm6,etc. (ThreadModeling) format."""
        if isinstance(data, (bytes, bytearray)):
            for opening_tag, closing_tag in [(b"<ThreatModel", b"</ThreatModel>"),
                                             (b"<KnowledgeBase", b"</KnowledgeBase>")]:
                opening_pos = data.find(opening_tag, 0, MAX_LINE_LENGTH)
                if 0 <= opening_pos < data.find(closing_tag, opening_pos):
                    # opening and closing tags were found - suppose it is an HTML
                    return True
        return False

    # A well-formed XML must start from < or a whitespace character
    XML_FIRST_BRACKET_PATTERN = re.compile(rb"^\s*<")
    XML_OPENING_TAG_PATTERN = re.compile(rb"<([0-9A-Za-z_]{1,256})")

    @staticmethod
    def is_xml(data: Union[bytes, bytearray]) -> bool:
        """Used to detect xml format from raw bytes"""
        if isinstance(data, (bytes, bytearray)) and Util.XML_FIRST_BRACKET_PATTERN.search(data, 0, MAX_LINE_LENGTH):
            if first_bracket_match := Util.XML_OPENING_TAG_PATTERN.search(data, 0, MAX_LINE_LENGTH):
                start_pos = first_bracket_match.start()
                closing_tag = b"</" + first_bracket_match.group(1) + b">"
                if start_pos < data.find(closing_tag, start_pos):
                    return True
        return False

    @staticmethod
    def is_eml(data: Union[bytes, bytearray]) -> bool:
        """According to https://datatracker.ietf.org/doc/html/rfc822 lookup the fields: Date, From, To or Subject"""
        if isinstance(data, (bytes, bytearray)) \
                and (b"\nDate:" in data or data.startswith(b"Date:")) \
                and (b"\nFrom:" in data or data.startswith(b"From:")) \
                and (b"\nTo:" in data or data.startswith(b"To:")) \
                and (b"\nSubject:" in data or data.startswith(b"Subject:")):
            return True
        return False

    @staticmethod
    def read_data(path: Union[str, Path]) -> Optional[bytes]:
        """Read the file bytes as is.

        Try to read the data of the file.

        Args:
            path: path to file

        Return:
            list of file rows in a suitable encoding from "encodings",
            if none of the encodings match, an empty list will be returned

        """

        try:
            with open(path, "rb") as file:
                return file.read()
        except Exception as exc:
            logger.error(f"Unexpected Error: Can not read '{path}'. Error message: '{exc}'")
        return None

    @staticmethod
    def get_xml_from_lines(xml_lines: List[str]) -> Tuple[Optional[List[str]], Optional[List[int]]]:
        """Parse xml data from list of string and return List of str.

        Args:
            xml_lines: list of lines of xml data

        Return:
            List of formatted string(f"{root.tag} : {root.text}")

        Raises:
            xml exception

        """
        lines = []
        line_nums = []
        tree = etree.fromstringlist(xml_lines)
        for element in tree.iter():
            tag = Util.extract_element_data(element, "tag")
            text = Util.extract_element_data(element, "text")
            lines.append(f"{tag} : {text}")
            line_nums.append(element.sourceline)
        return lines, line_nums

    @staticmethod
    def extract_element_data(element: Any, attr: str) -> str:
        """Extract xml element data to string.

        Try to extract the xml data and strip() the string.

        Args:
            element: xml element
            attr: attribute name

        Return:
            String xml data with strip()

        """
        element_attr: Any = getattr(element, attr)
        if element_attr is None or not isinstance(element_attr, str):
            return ''
        return str(element_attr).strip()

    @staticmethod
    def json_load(file_path: Union[str, Path], encoding=DEFAULT_ENCODING) -> Any:
        """Load dictionary from json file"""
        try:
            with open(file_path, "r", encoding=encoding) as f:
                return json.load(f)
        except Exception as exc:
            logging.error(f"Failed to read: {file_path} {exc}")
        return None

    @staticmethod
    def json_dump(obj: Any, file_path: Union[str, Path], encoding=DEFAULT_ENCODING, indent=4) -> None:
        """Write dictionary to json file"""
        try:
            with open(file_path, "w", encoding=encoding) as f:
                json.dump(obj, f, indent=indent)
        except Exception as exc:
            logging.error(f"Failed to write: {file_path} {exc}")

    @staticmethod
    def yaml_load(file_path: Union[str, Path], encoding=DEFAULT_ENCODING) -> Any:
        """Load dictionary from yaml file"""
        try:
            with open(file_path, "r", encoding=encoding) as f:
                return yaml.load(f, Loader=yaml.FullLoader)
        except Exception as exc:
            logger.error(f"Failed to read {file_path} {exc}")
        return None

    @staticmethod
    def yaml_dump(obj: Any, file_path: Union[str, Path], encoding=DEFAULT_ENCODING) -> None:
        """Write dictionary to yaml file"""
        try:
            with open(file_path, "w", encoding=encoding) as f:
                yaml.dump(obj, f)
        except Exception as exc:
            logging.error(f"Failed to write: {file_path} {exc}")

    @staticmethod
    def parse_python(source: str) -> List[Any]:
        """Parse python source and back to remove strings merge and line wrap"""
        src = ast.parse(source)
        result = ast.unparse(src).splitlines()
        return result

    PEM_CLEANING_PATTERN = re.compile(r"\\[tnrvf]")
    WHITESPACE_TRANS_TABLE = str.maketrans('', '', string.whitespace)

    @staticmethod
    def decode_base64(text: str, padding_safe: bool = False, urlsafe_detect=False) -> bytes:
        """decode text to bytes with / without padding detect and urlsafe symbols"""
        value = text.translate(Util.WHITESPACE_TRANS_TABLE)
        if padding_safe:
            value = value.rstrip('=')  # python 3.10 workaround
            pad_num = 0x3 & len(value)
            if pad_num:
                value += '=' * (4 - pad_num)
        if urlsafe_detect and ('-' in value or '_' in value):
            decoded = base64.b64decode(value, altchars=b"-_", validate=True)
        else:
            decoded = base64.b64decode(value, validate=True)
        return decoded

    @staticmethod
    def load_pk(data: bytes, password: Optional[bytes] = None) -> Optional[PrivateKeyTypes]:
        """Try to load private key from PKCS1, PKCS8 and PKCS12 formats"""
        with contextlib.suppress(Exception):
            # PKCS1, PKCS8 probes
            private_key = load_der_private_key(data, password)
            return private_key
        with contextlib.suppress(Exception):
            # PKCS12 probe
            private_key, _certificate, _additional_certificates = load_key_and_certificates(data, password)
            return private_key
        return None

    RANDOM_DATA = random.randbytes(20)

    @staticmethod
    def check_pk(pkey: PrivateKeyTypes) -> bool:
        """Check private key with encrypt-decrypt random data"""
        if isinstance(pkey, (EllipticCurvePrivateKey, DSAPrivateKey, Ed448PrivateKey, Ed25519PrivateKey, DHPrivateKey,
                             X448PrivateKey, X25519PrivateKey)):
            # One does not simply perform check the keys
            return True
        if isinstance(pkey, (EllipticCurvePublicKey, DSAPublicKey, Ed448PublicKey, Ed25519PublicKey, DHPublicKey,
                             X448PublicKey, X25519PublicKey)) or not pkey:
            # These aren't the keys we're looking for
            return False
            # DSA, RSA
        pd = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None)
        ciphertext = pkey.public_key().encrypt(Util.RANDOM_DATA, padding=pd)
        refurb = pkey.decrypt(ciphertext, padding=pd)
        return bool(refurb == Util.RANDOM_DATA)

    @staticmethod
    def get_chunks(line_len: int) -> List[Tuple[int, int]]:
        """Returns chunks positions for given line length"""
        # line length is over MAX_LINE_LENGTH already
        chunks = [(0, CHUNK_SIZE)]
        # case for oversize line
        next_offset = CHUNK_STEP_SIZE
        while line_len > next_offset:
            # the target is too long for single "finditer" - it will be scanned by chunks
            if line_len > next_offset + MAX_LINE_LENGTH:
                # the chunk is not the before last
                chunks.append((next_offset, next_offset + CHUNK_SIZE))
                next_offset += CHUNK_STEP_SIZE
            else:
                # the tail of line is between CHUNK_SIZE and MAX_LINE_LENGTH
                chunks.append((next_offset, line_len))
                break
        return chunks

    @staticmethod
    def subtext(text: str, pos: int, hunk_size: int) -> str:
        """cut text symmetrically for given position or use remained quota to be fitted in 2x hunk_size"""
        # cut trailed whitespaces to obtain more informative data
        text = text.rstrip()
        if hunk_size <= pos:
            left_quota = 0
            left_pos = pos - hunk_size
        else:
            left_quota = hunk_size - pos
            left_pos = 0
        # skip leading whitespaces in result string
        for i in range(left_pos, pos):
            if text[i] in string.whitespace:
                left_quota += 1
                left_pos += 1
            else:
                break
        right_remain = len(text) - pos
        if hunk_size <= right_remain:
            right_quota = 0
            right_pos = pos + hunk_size + left_quota
        else:
            right_quota = hunk_size - right_remain
            right_pos = pos + hunk_size + left_quota
        if len(text) < right_pos:
            right_pos = len(text)
        if 0 < left_pos:
            left_pos -= right_quota
            if 0 > left_pos:
                left_pos = 0
        return text[left_pos:right_pos].rstrip()

    @staticmethod
    def get_excel_column_name(column_index: int) -> str:
        """Converts index based column position into Excel style column name"""
        name = ''
        if isinstance(column_index, int):
            while 0 <= column_index:
                column_index, remain = divmod(column_index, 26)
                name = f"{chr(ord('A') + remain)}{name}"
                column_index -= 1
        return name
