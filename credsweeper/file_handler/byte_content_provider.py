from typing import List, Optional

from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.utils import Util


class ByteContentProvider(ContentProvider):
    """Allow to scan byte sequence.

    Parameters:
        content: byte sequence to be scanned.Would be automatically split into an array of lines in a new
          line character is present
        file_path: optional string. Might be specified if you know true file name lines was taken from

    """

    def __init__(self, content: bytes, file_path: Optional[str] = None) -> None:
        super().__init__(file_path if file_path is not None else "")
        self.lines = Util.decode_bytes(content)

    def get_analysis_target(self) -> List[AnalysisTarget]:
        """Return lines to scan.

        Return:
            list of analysis targets based on every row in a content

        """
        return self.lines_to_targets(self.lines)
