import logging
from functools import cached_property
from typing import Optional, Any, Generator

from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.content_provider import ContentProvider

logger = logging.getLogger(__name__)


class StructContentProvider(ContentProvider):
    """Content provider to keep structured data"""

    def __init__(
            self,  #
            struct: Any,  #
            file_path: Optional[str] = None,  #
            file_type: Optional[str] = None,  #
            info: Optional[str] = None) -> None:
        """
        Parameters:
            struct: Various structure (string, dictionary, list)

        """
        super().__init__(file_path=file_path, file_type=file_type, info=info)
        self.__struct = struct

    @cached_property
    def data(self) -> bytes:
        """data getter for StructContentProvider"""
        raise NotImplementedError(__name__)

    @cached_property
    def struct(self) -> Any:
        """struct getter for StructContentProvider"""
        return self.__struct

    def free(self) -> None:
        """free data after scan to reduce memory usage"""
        self.__struct = None
        if "struct" in self.__dict__:
            delattr(self, "struct")

    def yield_analysis_target(self, min_len: int) -> Generator[AnalysisTarget, None, None]:
        """Return nothing. The class provides only data storage.

        Args:
            min_len: minimal line length to scan

        Raise:
            NotImplementedError

        """
        raise NotImplementedError()
