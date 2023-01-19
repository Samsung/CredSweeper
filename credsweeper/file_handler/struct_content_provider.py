import logging
from typing import List, Optional, Any

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

    def get_analysis_target(self) -> List[AnalysisTarget]:
        """Return nothing. The class provides only data storage.

        Raise:
            NotImplementedError

        """
        raise NotImplementedError()
