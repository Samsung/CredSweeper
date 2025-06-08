import logging
from dataclasses import dataclass
from functools import cached_property
from typing import List, Tuple, Generator, TypedDict, Optional, Union, Any, Dict

import whatthepatch

from credsweeper.common.constants import DiffRowType
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.content_provider import ContentProvider

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


class DiffContentProvider(ContentProvider):
    """Provide data from a single `.patch` file.

    Parameters:
        file_path: path to file
        change_type: set added or deleted file data to scan
        diff: list of file row changes, with base elements represented as::

            {
                "old": line number before diff,
                "new": line number after diff,
                "line": line text,
                "hunk": diff hunk number
            }

    """

    def __init__(
            self,  #
            file_path: str,  #
            change_type: DiffRowType,  #
            diff: List[DiffDict]) -> None:
        super().__init__(file_path=file_path, info=f"{file_path}:{change_type.value}")
        self.__change_type = change_type
        self.__diff = diff

    @cached_property
    def data(self) -> bytes:
        """data getter for DiffContentProvider"""
        raise NotImplementedError(__name__)

    @cached_property
    def diff(self) -> List[DiffDict]:
        """diff getter for DiffContentProvider"""
        return self.__diff

    def free(self) -> None:
        """free data after scan to reduce memory usage"""
        self.__diff = []
        if "diff" in self.__dict__:
            delattr(self, "diff")

    @staticmethod
    def parse_lines_data(change_type: DiffRowType, lines_data: List[DiffRowData]) -> Tuple[List[int], List[str]]:
        """Parse diff lines data.

        Return list of line numbers with change type "self.change_type" and list of all lines in file
            in original order(replaced all lines not mentioned in diff file with blank line)

        Args:
            change_type: set added or deleted file data to scan
            lines_data: data of all rows mentioned in diff file

        Return:
            tuple of line numbers with change type "self.change_type" and all file lines
            in original order(replaced all lines not mentioned in diff file with blank line)

        """
        change_numbs = []
        all_lines = []
        for line_data in lines_data:
            if line_data.line_type == change_type:
                change_numbs.append(line_data.line_numb)
                all_lines.append(line_data.line)
        return change_numbs, all_lines

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
            if DiffContentProvider.wrong_change(change):
                continue
            line = change["line"]
            if isinstance(line, str):
                rows_data.extend(DiffContentProvider.preprocess_diff_rows(change.get("new"), change.get("old"), line))
            elif isinstance(line, (bytes, bytearray)):
                logger.warning("The feature is available with the deep scan option")
            else:
                logger.error(f"Unknown type of line {type(line)}")

        return rows_data

    def yield_analysis_target(self, min_len: int) -> Generator[AnalysisTarget, None, None]:
        """Preprocess file diff data to scan.

        Args:
            min_len: minimal line length to scan

        Return:
            list of analysis targets of every row of file diff corresponding to change type "self.change_type"

        """
        lines_data = DiffContentProvider.preprocess_file_diff(self.__diff)
        change_numbs, all_lines = self.parse_lines_data(self.__change_type, lines_data)
        return self.lines_to_targets(min_len, all_lines, change_numbs)
