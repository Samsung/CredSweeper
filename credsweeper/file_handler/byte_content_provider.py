from functools import cached_property
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
        self.__data = content
        self.__lines: Optional[List[str]] = None

    @cached_property
    def data(self) -> Optional[bytes]:
        """data RO getter for ByteContentProvider"""
        return self.__data

    def free(self) -> None:
        """free data after scan to reduce memory usage"""
        self.__data = None
        if hasattr(self, "data"):
            delattr(self, "data")
        self.__lines = None
        if hasattr(self, "lines"):
            delattr(self, "lines")

    @cached_property
    def lines(self) -> List[str]:
        """lines RO getter for ByteContentProvider"""
        if self.__lines is None:
            self.__lines = Util.decode_bytes(self.__data)
        return self.__lines if self.__lines is not None else []

    def yield_analysis_target(self, min_len: int) -> Generator[AnalysisTarget, None, None]:
        """Return lines to scan.

        Args:
            min_len: minimal line length to scan

        Return:
            list of analysis targets based on every row in a content

        """
        return self.lines_to_targets(min_len, self.lines)
