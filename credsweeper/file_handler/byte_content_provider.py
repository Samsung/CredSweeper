import logging
from typing import List, Optional

from credsweeper.common.constants import AVAILABLE_ENCODINGS
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.content_provider import ContentProvider


class ByteContentProvider(ContentProvider):
    """Allow to scan byte sequence.

    Parameters:
        content: byte sequence to be scanned.Would be automatically split into an array of lines in a new
          line character is present
        file_path: optional string. Might be specified if you know true file name lines was taken from

    """

    def __init__(self, content: bytes, file_path: Optional[str] = None) -> None:
        self.file_path = file_path if file_path is not None else ""

        self.lines = []
        for encoding in AVAILABLE_ENCODINGS:
            try:
                text = content.decode(encoding)
                self.lines = text.split("\n")
                break
            except UnicodeError:
                logging.info(f"UnicodeError: Can't read content as {encoding}.")
            except Exception as exc:
                logging.error(f"Unexpected Error: Can't read content as {encoding}. Error message: {exc}")

    def get_analysis_target(self) -> List[AnalysisTarget]:
        """Return lines to scan.

        Return:
            list of analysis targets based on every row in a content

        """
        return [AnalysisTarget(line, i + 1, self.lines, self.file_path) for i, line in enumerate(self.lines)]
