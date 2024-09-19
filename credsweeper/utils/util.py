import ast
import base64
import json
import logging
import math
import os
import string
import struct
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional, Union

import whatthepatch
import yaml
from lxml import etree
from typing_extensions import TypedDict

from credsweeper.common.constants import DiffRowType, AVAILABLE_ENCODINGS, \
    DEFAULT_ENCODING, LATIN_1, CHUNK_SIZE, MAX_LINE_LENGTH, CHUNK_STEP_SIZE

logger = logging.getLogger(__name__)

DiffDict = TypedDict(
    "DiffDict",
    {
        "old": Optional[int],  #
        "new": Optional[int],  #
        "line": Union[str, bytes],  # bytes are possibly since whatthepatch v1.0.4
        "hunk": Any  # not used
    })


@dataclass(frozen=True)
class DiffRowData:
    """Class for keeping data of diff row."""

    line_type: DiffRowType
    line_numb: int
    line: str


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
    def get_shannon_entropy(data: str, iterator: str) -> float:
        """Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html."""
        if not data:
            return 0

        entropy = 0.
        data_len = float(len(data))
        for x in iterator:
            p_x = data.count(x) / data_len
            if p_x > 0:
                entropy += -p_x * math.log(p_x, 2)

        return entropy

    """Precalculated data for speedup"""
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
    def is_binary(data: bytes) -> bool:
        """
        Returns true if any recognized binary format found
        or two zeroes sequence is found which never exists in text format (UTF-8, UTF-16)
        UTF-32 is not supported
        """
        if Util.is_zip(data) \
                or Util.is_gzip(data) \
                or Util.is_tar(data) \
                or Util.is_bzip2(data) \
                or Util.is_pdf(data) \
                or Util.is_elf(data):
            return True
        if b"\0\0" in data:
            return True
        non_ascii_cnt = 0
        for i in data[:MAX_LINE_LENGTH]:
            if 0x20 > i and i not in (0x09, 0x0A, 0x0D) or 0x7E < i < 0xA0:
                # less than space and not tab, line feed, line end
                non_ascii_cnt += 1
        if data:
            # experiment for 255217 binary files shown avg = 0.268264 ± 0.168767, so let choose minimal
            chunk_len = float(MAX_LINE_LENGTH if MAX_LINE_LENGTH < len(data) else len(data))
            result = 0.1 < non_ascii_cnt / chunk_len
        else:
            # empty data case
            result = False
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
        lines = []
        binary_suggest = False
        if encodings is None:
            encodings = AVAILABLE_ENCODINGS
        for encoding in encodings:
            try:
                if binary_suggest and LATIN_1 == encoding and Util.is_binary(content):
                    # LATIN_1 may convert data (bytes in range 0x80:0xFF are transformed)
                    # so skip this encoding when checking binaries
                    logger.warning("Binary file detected")
                    return []
                text = content.decode(encoding, errors="strict")
                if content != text.encode(encoding, errors="strict"):
                    raise UnicodeError
                # windows & macos styles workaround
                lines = text.replace('\r\n', '\n').replace('\r', '\n').split('\n')
                break
            except UnicodeError:
                binary_suggest = True
                logger.info(f"UnicodeError: Can't decode content as {encoding}.")
            except Exception as exc:
                logger.error(f"Unexpected Error: Can't read content as {encoding}. Error message: {exc}")
        return lines

    @staticmethod
    def patch2files_diff(raw_patch: List[str], change_type: DiffRowType) -> Dict[str, List[DiffDict]]:
        """Generate files changes from patch for added or deleted filepaths.

        Args:
            raw_patch: git patch file content
            change_type: change type to select, DiffRowType.ADDED or DiffRowType.DELETED

        Return:
            return dict with ``{file paths: list of file row changes}``, where
            elements of list of file row changes represented as::

                {
                    "old": line number before diff,
                    "new": line number after diff,
                    "line": line text,
                    "hunk": diff hunk number
                }

        """
        if not raw_patch:
            return {}

        added_files, deleted_files = {}, {}
        try:
            for patch in whatthepatch.parse_patch(raw_patch):
                if patch.changes is None:
                    logger.warning(f"Patch '{str(patch.header)}' cannot be scanned")
                    continue
                changes = []
                for change in patch.changes:
                    change_dict = change._asdict()
                    changes.append(change_dict)

                added_files[patch.header.new_path] = changes
                deleted_files[patch.header.old_path] = changes
            if change_type == DiffRowType.ADDED:
                return added_files
            elif change_type == DiffRowType.DELETED:
                return deleted_files
            else:
                logger.error(f"Change type should be one of: '{DiffRowType.ADDED}', '{DiffRowType.DELETED}';"
                             f" but received {change_type}")
        except Exception as exc:
            logger.exception(exc)
        return {}

    @staticmethod
    def preprocess_diff_rows(
            added_line_number: Optional[int],  #
            deleted_line_number: Optional[int],  #
            line: str) -> List[DiffRowData]:
        """Auxiliary function to extend diff changes.

        Args:
            added_line_number: number of added line or None
            deleted_line_number: number of deleted line or None
            line: the text line

        Return:
            diff rows data with as list of row change type, line number, row content

        """
        rows_data: List[DiffRowData] = []
        if isinstance(added_line_number, int):
            # indicates line was inserted
            rows_data.append(DiffRowData(DiffRowType.ADDED, added_line_number, line))
        if isinstance(deleted_line_number, int):
            # indicates line was removed
            rows_data.append(DiffRowData(DiffRowType.DELETED, deleted_line_number, line))
        return rows_data

    @staticmethod
    def wrong_change(change: DiffDict) -> bool:
        """Returns True if the change is wrong"""
        for i in ["line", "new", "old"]:
            if i not in change:
                logger.error(f"Skipping wrong change {change}")
                return True
        return False

    @staticmethod
    def preprocess_file_diff(changes: List[DiffDict]) -> List[DiffRowData]:
        """Generate changed file rows from diff data with changed lines (e.g. marked + or - in diff).

        Args:
            changes: git diff by file rows data

        Return:
            diff rows data with as list of row change type, line number, row content

        """
        if not changes:
            return []

        rows_data = []
        # process diff to restore lines and their positions
        for change in changes:
            if Util.wrong_change(change):
                continue
            line = change["line"]
            if isinstance(line, str):
                rows_data.extend(Util.preprocess_diff_rows(change.get("new"), change.get("old"), line))
            elif isinstance(line, bytes):
                logger.warning("The feature is available with the deep scan option")
            else:
                logger.error(f"Unknown type of line {type(line)}")

        return rows_data

    @staticmethod
    def is_zip(data: bytes) -> bool:
        """According https://en.wikipedia.org/wiki/List_of_file_signatures"""
        if isinstance(data, bytes) and 3 < len(data):
            # PK
            if data.startswith(b"PK"):
                if 0x03 == data[2] and 0x04 == data[3]:
                    return True
                # empty archive - no sense to scan
                elif 0x05 == data[2] and 0x06 == data[3]:
                    return True
                # spanned archive - NOT SUPPORTED
                elif 0x07 == data[2] and 0x08 == data[3]:
                    return False
        return False

    @staticmethod
    def is_tar(data: bytes) -> bool:
        """According https://en.wikipedia.org/wiki/List_of_file_signatures"""
        if isinstance(data, bytes) and 512 <= len(data):
            if 0x75 == data[257] and 0x73 == data[258] and 0x74 == data[259] \
                    and 0x61 == data[260] and 0x72 == data[261] and (
                    0x00 == data[262] and 0x30 == data[263] and 0x30 == data[264]
                    or
                    0x20 == data[262] and 0x20 == data[263] and 0x00 == data[264]
            ):
                try:
                    chksum = tarfile.nti(data[148:156])  # type: ignore
                    unsigned_chksum, signed_chksum = tarfile.calc_chksums(data)  # type: ignore
                    return bool(chksum == unsigned_chksum or chksum == signed_chksum)
                except Exception as exc:
                    logger.exception(f"Corrupted TAR ? {exc}")
        return False

    @staticmethod
    def is_bzip2(data: bytes) -> bool:
        """According https://en.wikipedia.org/wiki/Bzip2"""
        if isinstance(data, bytes) and 10 <= len(data):
            if data.startswith(b"\x42\x5A\x68") \
                    and 0x31 <= data[3] <= 0x39 \
                    and 0x31 == data[4] and 0x41 == data[5] and 0x59 == data[6] \
                    and 0x26 == data[7] and 0x53 == data[8] and 0x59 == data[9]:
                return True
        return False

    @staticmethod
    def is_gzip(data: bytes) -> bool:
        """According https://www.rfc-editor.org/rfc/rfc1952"""
        if isinstance(data, bytes) and 3 <= len(data):
            if data.startswith(b"\x1F\x8B\x08"):
                return True
        return False

    @staticmethod
    def is_pdf(data: bytes) -> bool:
        """According https://en.wikipedia.org/wiki/List_of_file_signatures - pdf"""
        if isinstance(data, bytes) and 5 <= len(data):
            if data.startswith(b"\x25\x50\x44\x46\x2D"):
                return True
        return False

    @staticmethod
    def is_jks(data: bytes) -> bool:
        """According https://en.wikipedia.org/wiki/List_of_file_signatures - jks"""
        if isinstance(data, bytes) and 4 <= len(data):
            if data.startswith(b"\xFE\xED\xFE\xED"):
                return True
        return False

    @staticmethod
    def is_asn1(data: bytes) -> bool:
        """Only sequence type 0x30 and size correctness is checked"""
        data_length = len(data)
        if isinstance(data, bytes) and 4 <= data_length:
            # sequence
            if 0x30 == data[0]:
                # https://www.oss.com/asn1/resources/asn1-made-simple/asn1-quick-reference/basic-encoding-rules.html#Lengths
                length = data[1]
                byte_len = (0x7F & length)
                if 0x80 == length and data.endswith(b"\x00\x00"):
                    return True
                elif 0x80 < length and 1 < byte_len < data_length:  # additional check
                    len_bytes = data[2:2 + byte_len]
                    try:
                        long_size = struct.unpack(">h", len_bytes)
                    except struct.error:
                        long_size = (-1,)  # yapf: disable
                    length = long_size[0]
                elif 0x80 < length and 1 == byte_len:  # small size
                    length = data[2]
                else:
                    byte_len = 0
                return data_length == length + 2 + byte_len
        return False

    @staticmethod
    def is_elf(data: Union[bytes, bytearray]) -> bool:
        """According to https://en.wikipedia.org/wiki/Executable_and_Linkable_Format use only 5 bytes"""
        if isinstance(data, (bytes, bytearray)) and 127 <= len(data):
            # minimal is 127 bytes https://github.com/tchajed/minimal-elf
            if data.startswith(b"\x7f\x45\x4c\x46") and (0x01 == data[5] or 0x02 == data[5]):
                return True
        return False

    @staticmethod
    def is_html(data: Union[bytes, bytearray]) -> bool:
        """Used to detect html format of eml"""
        if isinstance(data, (bytes, bytearray)):
            if b"<html" in data and b"</html>" in data:
                return True
        return False

    @staticmethod
    def is_eml(data: Union[bytes, bytearray]) -> bool:
        """According to https://datatracker.ietf.org/doc/html/rfc822 lookup the fields: Date, From, To or Subject"""
        if isinstance(data, (bytes, bytearray)):
            if ((b"\nDate:" in data or data.startswith(b"Date:"))  #
                    and (b"\nFrom:" in data or data.startswith(b"From:"))  #
                    and (b"\nTo:" in data or data.startswith(b"To:")  #
                         or b"\nSubject:" in data or data.startswith(b"Subject:"))):
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
            tag = Util._extract_element_data(element, "tag")
            text = Util._extract_element_data(element, "text")
            lines.append(f"{tag} : {text}")
            line_nums.append(element.sourceline)
        return lines, line_nums

    @staticmethod
    def _extract_element_data(element, attr) -> str:
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
            return ""
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
    def __extract_value(node: Any, value: Any) -> List[Any]:
        result = []
        for i in getattr(node, "targets"):
            if hasattr(i, "id"):
                result.append({getattr(i, "id"): value})
            else:
                logger.error(f"{str(i)} has no 'id'")
        return result

    @staticmethod
    def __extract_assign(node: Any) -> List[Any]:
        result = []
        if hasattr(node, "value") and hasattr(node, "targets"):
            value = getattr(node, "value")
            if hasattr(value, "value"):
                # python 3.8 - 3.10
                result.extend(Util.__extract_value(node, getattr(value, "value")))
            else:
                logger.error(f"value.{value} has no 'value' {dir(value)}")
        else:
            logger.error(f"{str(node)} has no 'value' {dir(node)}")
        return result

    @staticmethod
    def ast_to_dict(node: Any) -> List[Any]:
        """Recursive parsing AST tree of python source to list with strings"""
        result: List[Any] = []
        if hasattr(node, "value") and isinstance(node.value, str):
            result.append(node.value)

        if isinstance(node, ast.Module) \
                or isinstance(node, ast.FunctionDef):
            if hasattr(node, "body"):
                for i in node.body:
                    x = Util.ast_to_dict(i)
                    if x:
                        result.extend(x)
        elif isinstance(node, ast.Import):
            logger.debug("Import:%s", str(node))
        elif isinstance(node, ast.Assign):
            result.extend(Util.__extract_assign(node))
        elif isinstance(node, ast.Expr) \
                or isinstance(node, ast.AnnAssign) \
                or isinstance(node, ast.AugAssign) \
                or isinstance(node, ast.Call) \
                or isinstance(node, ast.JoinedStr) \
                or isinstance(node, ast.Return) \
                or isinstance(node, ast.ImportFrom) \
                or isinstance(node, ast.Assert) \
                or isinstance(node, ast.Pass) \
                or isinstance(node, ast.Raise) \
                or isinstance(node, ast.Str) \
                or isinstance(node, ast.Name) \
                or isinstance(node, ast.FormattedValue) \
                or isinstance(node, ast.Global):
            if hasattr(node, "value"):
                result.extend(Util.ast_to_dict(getattr(node, "value")))
            if hasattr(node, "args"):
                for i in getattr(node, "args"):
                    result.extend(Util.ast_to_dict(i))
            if hasattr(node, "values"):
                for i in getattr(node, "values"):
                    result.extend(Util.ast_to_dict(i))
            else:
                logger.debug(f"skip:{str(node)}")
        else:
            logger.debug(f"unknown:{str(node)}")
        return result

    @staticmethod
    def parse_python(source: str) -> List[Any]:
        """Parse python source to list of strings and assignments"""
        src = ast.parse(source)
        result = Util.ast_to_dict(src)
        return result

    @staticmethod
    def decode_base64(text: str, padding_safe: bool = False, urlsafe_detect=False) -> bytes:
        """decode text to bytes with / without padding detect and urlsafe symbols"""
        value = text
        if padding_safe:
            pad_num = 0x3 & len(value)
            if pad_num:
                value += '=' * (4 - pad_num)
        if urlsafe_detect and ('-' in value or '_' in value):
            decoded = base64.b64decode(value, altchars=b"-_", validate=True)
        else:
            decoded = base64.b64decode(value, validate=True)
        return decoded

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
