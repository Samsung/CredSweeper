from typing import Dict, List, Tuple

from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.utils import DiffRowData, Util


class DiffContentProvider(ContentProvider):
    """Provide data from a single `.patch` file.

    Attributes:
        self.file_path: string, path to file
        self.change_type: string, set added or deleted file data to scan
        self.diff: list of file row changes, where base elements represented as:
            {
                "old": line number before diff,
                "new": line number after diff,
                "line": line text,
                "hunk": diff hunk number
            }

    """
    def __init__(self,
                 file_path: str,
                 change_type: str,
                 diff: List[Dict]) -> None:
        self.change_type = change_type
        self.diff = diff
        self.file_path = file_path

    def parse_lines_data(self, lines_data: List[DiffRowData]) -> Tuple[List[int], List[str]]:
        """Parse diff lines data

        Return list of line numbers with change type "self.change_type" and list of all lines in file
            in original order(replaced all lines not mentioned in diff file with blank line)

        Args:
            lines_data: list of DiffRowData object, data of all rows mentioned in diff file

        Return:
            change_numbs: list of integer, line numbers with change type "self.change_type"
            all_lines: all file lines in original order(replaced all lines not mentioned in diff file with blank line)
        """
        max_line_numbs = max(x.line_numb for x in lines_data)
        all_lines = [""] * max_line_numbs
        change_numbs = []
        for line_data in lines_data:
            if line_data.line_type.startswith(self.change_type):
                all_lines[line_data.line_numb - 1] = line_data.line
            if line_data.line_type == self.change_type:
                change_numbs.append(line_data.line_numb)
        return change_numbs, all_lines

    def get_analysis_target(self) -> List[AnalysisTarget]:
        """Preprocess file diff data to scan

        Return:
            list of analysis targets of every row of file diff corresponding to change type "self.change_type"
        """
        lines_data = Util.preprocess_file_diff(self.diff)
        change_numbs, all_lines = self.parse_lines_data(lines_data)
        return [AnalysisTarget(all_lines[l_numb - 1], l_numb, all_lines, self.file_path) for l_numb in change_numbs]
