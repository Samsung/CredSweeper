from typing import List, Optional, Generator

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
        self.data = content
        self.__lines: Optional[List[str]] = None

    @property
    def data(self) -> Optional[bytes]:
        """data getter for ByteContentProvider"""
        return self.__data

    @data.setter
    def data(self, data: Optional[bytes]) -> None:
        """data setter for ByteContentProvider"""
        self.__data = data

    @property
    def lines(self) -> List[str]:
        """lines getter for ByteContentProvider"""
        if self.__lines is None:
            self.__lines = Util.decode_bytes(self.__data)
        return self.__lines if self.__lines is not None else []

    @lines.setter
    def lines(self, lines: List[str]) -> None:
        """lines setter for ByteContentProvider"""
        self.__lines = lines

    def yield_analysis_target(self, min_len: int) -> Generator[AnalysisTarget, None, None]:
        """Return lines to scan.

        Args:
            min_len: minimal line length to scan

        Return:
            list of analysis targets based on every row in a content

        """
        return self.lines_to_targets(min_len, self.lines)
