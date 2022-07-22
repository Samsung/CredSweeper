from typing import Dict, List, Optional

from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.utils import Util


class TextContentProvider(ContentProvider):
    """Provide access to analysis targets for full-text file scanning.

    Parameters:
        file_path: string, path to file

    """

    def __init__(self, file_path: str, change_type: Optional[str] = None, diff: Optional[List[Dict]] = None) -> None:
        super().__init__(file_path)

    def get_analysis_target(self) -> List[AnalysisTarget]:
        """Load and preprocess file content to scan.

        Return:
            list of analysis targets based on every row in file

        """
        lines = Util.read_file(self.file_path)
        return self.lines_to_targets(lines)
