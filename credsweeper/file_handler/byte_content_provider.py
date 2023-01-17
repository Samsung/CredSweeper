from typing import List, Optional

from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.utils import Util


class ByteContentProvider(ContentProvider):
    """Allow to scan byte sequence instead of extra reading a file"""

    def __init__(
            self,  #
            content: bytes,  #
            file_path: Optional[str] = None,  #
            file_type: Optional[str] = None,  #
            info: Optional[str] = None) -> None:
        """
        Parameters:
            content: The bytes are transformed to an array of lines with split by new line character.

        """
        super().__init__(file_path=file_path, file_type=file_type, info=info)
        self.lines = Util.decode_bytes(content)

    def get_analysis_target(self) -> List[AnalysisTarget]:
        """Return lines to scan.

        Return:
            list of analysis targets based on every row in a content

        """
        return self.lines_to_targets(self.lines)
