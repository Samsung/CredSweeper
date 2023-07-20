import logging
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
        self.struct = struct

    @property
    def struct(self) -> Any:
        """obj getter"""
        return self.__struct

    @struct.setter
    def struct(self, struct: Any) -> None:
        """obj setter"""
        self.__struct = struct

    @property
    def data(self) -> bytes:
        """data getter for StructContentProvider"""
        raise NotImplementedError(__name__)

    @data.setter
    def data(self, data: bytes) -> None:
        """data setter for StructContentProvider"""
        raise NotImplementedError(__name__)

    def yield_analysis_target(self, min_len: int) -> Generator[AnalysisTarget, None, None]:
        """Return nothing. The class provides only data storage.

        Args:
            min_len: minimal line length to scan

        Raise:
            NotImplementedError

        """
        raise NotImplementedError()
