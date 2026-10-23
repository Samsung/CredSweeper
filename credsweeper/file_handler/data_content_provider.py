import logging
from functools import cached_property
from typing import List, Optional, Generator

from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class DataContentProvider(ContentProvider):
    """Dummy raw provider to keep bytes"""

    def __init__(
            self,  #
            data: bytes,  #
            file_path: Optional[str] = None,  #
            file_type: Optional[str] = None,  #
            info: Optional[str] = None) -> None:
        """
        Parameters:
            data: byte sequence to be stored for deep analysis

        """
        super().__init__(file_path=file_path, file_type=file_type, info=info)
        self.__data = data
        self.__text: Optional[str] = None
        self.__lines: Optional[List[str]] = None

    @cached_property
    def data(self) -> Optional[bytes]:
        """data RO getter for DataContentProvider and the property is used in deep scan"""
        return self.__data

    def free(self) -> None:
        """free data after scan to reduce memory usage"""
        self.__data = None
        if "data" in self.__dict__:
            delattr(self, "data")
        self.__text = None
        if "text" in self.__dict__:
            delattr(self, "text")
        self.__lines = None
        if "lines" in self.__dict__:
            delattr(self, "lines")

    @cached_property
    def text(self) -> str:
        """Getter to produce a text from DEFAULT_ENCODING. Empty str for unrecognized data"""
        if self.__text is None:
            self.__text = Util.decode_text(self.__data) or ''
        return self.__text

    @cached_property
    def lines(self) -> List[str]:
        """lines RO getter for DataContentProvider"""
        if self.__lines is None:
            self.__lines = Util.split_text(self.text)
        return self.__lines

    def yield_analysis_target(self, min_len: int) -> Generator[AnalysisTarget, None, None]:
        """Return nothing. The class provides only data storage.

        Args:
            min_len: minimal line length to scan

        Raise:
            NotImplementedError

        """
        raise NotImplementedError()
