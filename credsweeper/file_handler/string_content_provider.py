from typing import List, Optional

from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.content_provider import ContentProvider


class StringContentProvider(ContentProvider):
    """Allow to scan array of lines.

    Parameters:
        lines: lines to be processed
        file_path: optional string. Might be specified if you know true file name lines was taken from

    """

    def __init__(self, lines: List[str], file_path: Optional[str] = None) -> None:
        super().__init__(file_path if file_path is not None else "")
        self.lines = lines

    def get_analysis_target(self) -> List[AnalysisTarget]:
        """Return lines to scan.

        Return:
            list of analysis targets based on every row in file

        """
        return [AnalysisTarget(line, i + 1, self.lines, self.file_path) for i, line in enumerate(self.lines)]
