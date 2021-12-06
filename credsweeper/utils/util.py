import logging
import math
import os
from dataclasses import dataclass
from typing import Dict, List

from regex import regex
import whatthepatch

from credsweeper.common.constants import Chars, DiffRowType, KeywordPattern, Separator


@dataclass
class DiffRowData:
    """Class for keeping data of diff row."""
    line_type: str
    line_numb: int
    line: str


class Util:
    """
    Class that contains different useful methods
    """
    default_encodings = ["utf8", "utf16", "latin_1"]

    @classmethod
    def get_extension(cls, file_path: str) -> str:
        _, extension = os.path.splitext(file_path)
        return extension

    @classmethod
    def get_keyword_pattern(cls, keyword: str, separator: Separator = Separator.common) -> regex.Pattern:
        return regex.compile(KeywordPattern.key.format(keyword) + KeywordPattern.separator.format(separator) +
                             KeywordPattern.value,
                             flags=regex.IGNORECASE)

    @classmethod
    def get_regex_combine_or(cls, regex_strs: List[str]) -> str:
        result = "(?:"

        for elem in regex_strs:
            result += elem + "|"

        if result[-1] == "|":
            result = result[:-1]
        result += ")"

        return result

    @classmethod
    def is_entropy_validate(cls, data: str) -> bool:
        if cls.get_shannon_entropy(data, Chars.BASE64_CHARS) > 4.5 or \
           cls.get_shannon_entropy(data, Chars.HEX_CHARS) > 3 or \
           cls.get_shannon_entropy(data, Chars.BASE36_CHARS) > 3:
            return True
        return False

    @classmethod
    def get_shannon_entropy(cls, data: str, iterator: Chars) -> float:
        """
        Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
        """
        if not data:
            return 0

        entropy = 0
        for x in iterator:
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log(p_x, 2)

        return entropy

    @classmethod
    def read_file(cls, path: str, encodings: List[str] = default_encodings) -> List[str]:
        """
        Read the file content using different encodings

        Try to read the contents of the file according to the list of encodings "encodings" as soon as reading
        occurs without any exceptions, the data is returned in the current encoding

        Args:
            path: string, path to file
            encodings: list of string, supported encodings

        Return:
            diff_data: list of string, list of file rows in a suitable encoding from "encodings",
                if none of the encodings match, an empty list will be returned
        """
        diff_data = []
        for encoding in encodings:
            try:
                with open(path, "r", encoding=encoding) as file:
                    diff_data = file.read().split("\n")
                break
            except UnicodeError:
                logging.warning(f"UnicodeError: Can't read content from \"{path}\" as {encoding}.")
            except Exception as exc:
                logging.error(f"Unexpected Error: Can't read \"{path}\" as {encoding}. Error message: {exc}")
        return diff_data

    @classmethod
    def patch2files_diff(cls, raw_patch: List[str], change_type: str) -> Dict[str, List[Dict]]:
        """Generates files rows from diff with only added and deleted lines (e.g. marked + or - in diff)

        Args:
            raw_patch: string variable, Git diff output

        Return:
            return dict with {file paths:list of file row changes}, where
                elements of list of file row changes represented as:
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

    @classmethod
    def preprocess_file_diff(cls, changes: List[Dict]) -> List[DiffRowData]:
        """Generates files rows from diff with only added and deleted lines (e.g. marked + or - in diff)

        Args:
            out: string variable, Git diff output

        Return:
            Tuple of to lists: list of line numbers and list of line texts
        """
        rows_data = []
        if changes is None:
            return []

        # process diff to restore lines and their positions
        for change in changes:
            if change.get("old") is None:
                # indicates line was inserted
                rows_data.append(DiffRowData(DiffRowType.ADDED, change.get("new"), change.get("line")))
            elif change.get("new") is None:
                # indicates line was removed
                rows_data.append(DiffRowData(DiffRowType.DELETED, change.get("old"), change.get("line")))
            else:
                rows_data.append(DiffRowData(DiffRowType.ADDED_ACCOMPANY, change.get("new"), change.get("line")))
                rows_data.append(DiffRowData(DiffRowType.DELETED_ACCOMPANY, change.get("old"), change.get("line")))

        return rows_data
