import logging
from functools import cached_property
from typing import List, Optional, Generator

from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


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
        if "data" in self.__dict__:
            delattr(self, "data")
        self.__lines = None
        if "lines" in self.__dict__:
            delattr(self, "lines")

    @cached_property
    def lines(self) -> List[str]:
        """lines RO getter for ByteContentProvider"""
        if self.__lines is None:
            text = Util.decode_text(self.__data)
            if text is None:
                logger.warning("Binary data detected %s %s %s", self.file_path, self.info,
                               repr(self.__data[:32]) if isinstance(self.__data, bytes) else "NONE")
                self.__lines = []
            else:
                self.__lines = Util.split_text(text)
        return self.__lines if self.__lines is not None else []

    def yield_analysis_target(self, min_len: int) -> Generator[AnalysisTarget, None, None]:
        """Return lines to scan.

        Args:
            min_len: minimal line length to scan

        Return:
            list of analysis targets based on every row in a content

        """
        return self.lines_to_targets(min_len, self.lines)
