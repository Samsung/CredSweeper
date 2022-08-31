import logging
from typing import List, Optional, Union

from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.content_provider import ContentProvider

logger = logging.getLogger(__name__)


class StructContentProvider(ContentProvider):
    """Dummy raw provider to keep structured data

    Parameters:
        struct: byte sequence to be stored.
        file_path: optional string. Might be specified if you know true file name lines was taken from.

    """

    def __init__(self, struct: Union[dict, list], file_path: Optional[str] = None, info: Optional[str] = None) -> None:
        super().__init__(file_path if file_path is not None else "", info if info is not None else "")
        self.struct = struct

    @property
    def struct(self) -> dict:
        """obj getter"""
        return self.__struct

    @struct.setter
    def struct(self, struct: dict) -> None:
        """obj setter"""
        self.__struct = struct

    def get_analysis_target(self) -> List[AnalysisTarget]:
        """Return nothing. The class provides only data storage.

        Raise:
            NotImplementedError

        """
        raise NotImplementedError()
