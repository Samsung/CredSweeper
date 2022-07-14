import logging
import math
import os
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional
from typing_extensions import TypedDict

import whatthepatch
from regex import regex

from credsweeper.common.constants import Chars, DiffRowType, KeywordPattern, Separator, AVAILABLE_ENCODINGS

DiffDict = TypedDict(
    "DiffDict",
    {
        "old": int,  #
        "new": int,  #
        "line": str,  #
        "hunk": str  #
    })


@dataclass
class DiffRowData:
    """Class for keeping data of diff row."""

    line_type: str
    line_numb: int
    line: str


class Util:
    """Class that contains different useful methods."""

    default_encodings: Tuple[str, ...] = AVAILABLE_ENCODINGS

    @staticmethod
    def get_extension(file_path: str) -> str:
        """Return extension of file e.g.: '.txt'"""
        _, extension = os.path.splitext(file_path)
        return extension

    @staticmethod
    def get_keyword_pattern(keyword: str, separator: str = Separator.common) -> regex.Pattern:
        """Returns compiled regex pattern"""
        return regex.compile(KeywordPattern.key.format(keyword) + KeywordPattern.separator.format(separator) +
                             KeywordPattern.value,
                             flags=regex.IGNORECASE)

    @staticmethod
    def get_regex_combine_or(regex_strs: List[str]) -> str:
        """Routine combination for regex 'or'"""
        result = "(?:"

        for elem in regex_strs:
            result += elem + "|"

        if result[-1] == "|":
            result = result[:-1]
        result += ")"

        return result

    @staticmethod
    def is_entropy_validate(data: str) -> bool:
        """Verifies data entropy with base64, base36 and base16(hex)"""
        # Replaced to the steps due: 1 - coverage 2 - YAPF
        if Util.get_shannon_entropy(data, Chars.BASE64_CHARS.value) > 4.5:
            return True
        elif Util.get_shannon_entropy(data, Chars.BASE36_CHARS.value) > 3:
            return True
        elif Util.get_shannon_entropy(data, Chars.HEX_CHARS.value) > 3:
            return True
        else:
            return False

    @staticmethod
    def get_shannon_entropy(data: str, iterator: str) -> float:
        """Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html."""
        if not data:
            return 0

        entropy = 0.
        for x in iterator:
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log(p_x, 2)

        return entropy

    @staticmethod
    def read_file(path: str, encodings: Tuple[str, ...] = default_encodings) -> List[str]:
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
        file_data = []
        for encoding in encodings:
            try:
                with open(path, "r", encoding=encoding) as file:
                    file_data = file.read().split("\n")
                break
            except UnicodeError:
                logging.info(f"UnicodeError: Can't read content from \"{path}\" as {encoding}.")
            except Exception as exc:
                logging.error(f"Unexpected Error: Can't read \"{path}\" as {encoding}. Error message: {exc}")
        return file_data

    @staticmethod
    def decode_bytes(content: bytes, encodings: Tuple[str, ...] = default_encodings) -> List[str]:
        """Decode content using different encodings.

        Try to decode bytes according to the list of encodings "encodings"
        occurs without any exceptions. UTF-16 requires BOM

        Args:
            content: raw data that might be text
            encodings: supported encodings

        Return:
            list of file rows in a suitable encoding from "encodings",
            if none of the encodings match, an empty list will be returned

        """
        lines = []
        for encoding in encodings:
            try:
                text = content.decode(encoding)
                if content != text.encode(encoding):
                    raise UnicodeError
                # windows style workaround
                lines = text.replace('\r\n', '\n').replace('\r', '\n').split("\n")
                break
            except UnicodeError:
                logging.info(f"UnicodeError: Can't decode content as {encoding}.")
            except Exception as exc:
                logging.error(f"Unexpected Error: Can't read content as {encoding}. Error message: {exc}")
        return lines

    @staticmethod
    def patch2files_diff(raw_patch: List[str], change_type: str) -> Dict[str, List[DiffDict]]:
        """Generate files changes from patch for added or deleted filepaths.

        Args:
            raw_patch: git patch file content
            change_type: change type to select, "added" or "deleted"

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

        # parse diff to patches
        patches = list(whatthepatch.parse_patch(raw_patch))
        added_files, deleted_files = {}, {}
        for patch in patches:
            if patch.changes is None:
                logging.warning(f"Patch '{str(patch.header)}' cannot be scanned")
                continue
            changes = []
            for change in patch.changes:
                changes.append(change._asdict())

            added_files[patch.header.new_path] = changes
            deleted_files[patch.header.old_path] = changes
        if change_type == "added":
            return added_files
        elif change_type == "deleted":
            return deleted_files
        else:
            logging.error(f"Change type should be one of: 'added', 'deleted'; but received {change_type}")
        return {}

    @staticmethod
    def preprocess_file_diff(changes: List[DiffDict]) -> List[DiffRowData]:
        """Generate changed file rows from diff data with changed lines (e.g. marked + or - in diff).

        Args:
            changes: git diff by file rows data

        Return:
            diff rows data with as list of row change type, line number, row content

        """
        rows_data = []
        if changes is None:
            return []

        # process diff to restore lines and their positions
        for change in changes:
            if change.get("old") is None:
                # indicates line was inserted
                rows_data.append(DiffRowData(DiffRowType.ADDED, change["new"], change["line"]))
            elif change.get("new") is None:
                # indicates line was removed
                rows_data.append(DiffRowData(DiffRowType.DELETED, change["old"], change["line"]))
            else:
                rows_data.append(DiffRowData(DiffRowType.ADDED_ACCOMPANY, change["new"], change["line"]))
                rows_data.append(DiffRowData(DiffRowType.DELETED_ACCOMPANY, change["old"], change["line"]))

        return rows_data

    @staticmethod
    def is_zip(data: bytes) -> bool:
        """According https://en.wikipedia.org/wiki/List_of_file_signatures"""
        if isinstance(data, bytes) and 3 < len(data):
            # PK
            if 0x50 == data[0] and 0x4B == data[1]:
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
    def read_data(path: str) -> Optional[bytes]:
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
            logging.error(f"Unexpected Error: Can not read '{path}'. Error message: '{exc}'")
        return None
