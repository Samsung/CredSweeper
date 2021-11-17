from typing import Dict, List

from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.utils import Util


class DiffContentProvider(ContentProvider):
    """Provide access to analysis targets of file diff to scan

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

    def get_analysis_target(self) -> List[AnalysisTarget]:
        """Preprocess file diff data to scan

        Return:
            list of analysis targets of every row of file diff corresponding to change type "self.change_type"
        """
        line_numbs, lines = Util.preprocess_file_diff(self.diff, self.change_type)
        return [AnalysisTarget(line, line_numb, lines, self.file_path) for line_numb, line in zip(line_numbs, lines)]
