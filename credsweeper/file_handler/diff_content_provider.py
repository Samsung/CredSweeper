import logging
from typing import List, Tuple, Generator

from credsweeper.common.constants import DiffRowType
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.utils import DiffRowData, Util, DiffDict

logger = logging.getLogger(__name__)


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
        super().__init__(file_path=file_path, info=change_type.value)
        self.change_type = change_type
        self.diff = diff

    @property
    def data(self) -> bytes:
        """data getter for DiffContentProvider"""
        raise NotImplementedError(__name__)

    @data.setter
    def data(self, data: bytes) -> None:
        """data setter for DiffContentProvider"""
        raise NotImplementedError(__name__)

    def parse_lines_data(self, lines_data: List[DiffRowData]) -> Tuple[List[int], List[str]]:
        """Parse diff lines data.

        Return list of line numbers with change type "self.change_type" and list of all lines in file
            in original order(replaced all lines not mentioned in diff file with blank line)

        Args:
            lines_data: data of all rows mentioned in diff file

        Return:
            tuple of line numbers with change type "self.change_type" and all file lines
            in original order(replaced all lines not mentioned in diff file with blank line)

        """
        change_numbs = []
        all_lines = []
        for line_data in lines_data:
            if line_data.line_type == self.change_type:
                change_numbs.append(line_data.line_numb)
                all_lines.append(line_data.line)
        return change_numbs, all_lines

    def yield_analysis_target(self, min_len: int) -> Generator[AnalysisTarget, None, None]:
        """Preprocess file diff data to scan.

        Args:
            min_len: minimal line length to scan

        Return:
            list of analysis targets of every row of file diff corresponding to change type "self.change_type"

        """
        lines_data = Util.preprocess_file_diff(self.diff)
        change_numbs, all_lines = self.parse_lines_data(lines_data)
        return self.lines_to_targets(min_len, all_lines, change_numbs)
