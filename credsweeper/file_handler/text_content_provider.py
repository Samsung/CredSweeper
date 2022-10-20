import logging
from typing import List, Optional

from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.utils import Util

logger = logging.getLogger(__name__)


class TextContentProvider(ContentProvider):
    """Provide access to analysis targets for full-text file scanning.

    Parameters:
        file_path: string, path to file

    """

    def __init__(
            self,
            file_path: str,  #
            file_type: Optional[str] = None,  #
            info: Optional[str] = None) -> None:
        super().__init__(file_path=file_path, file_type=file_type, info=info)

    def get_analysis_target(self) -> List[AnalysisTarget]:
        """Load and preprocess file content to scan.

        Return:
            list of analysis targets based on every row in file

        """
        lines: Optional[List[str]] = None
        line_nums: List[int] = []

        if Util.get_extension(self.file_path) == ".xml":
            lines, line_nums = Util.get_xml_data(self.file_path)

        if lines is None:
            lines = Util.read_file(self.file_path)

        return self.lines_to_targets(lines, line_nums)
