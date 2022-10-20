from typing import List, Optional

from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.content_provider import ContentProvider


class DataContentProvider(ContentProvider):
    """Dummy raw provider to keep bytes

    Parameters:
        data: byte sequence to be stored.
        file_path: optional string. Might be specified if you know true file name lines was taken from.

    """

    def __init__(
            self,  #
            data: bytes,  #
            file_path: Optional[str] = None,  #
            file_type: Optional[str] = None,  #
            info: Optional[str] = None) -> None:
        super().__init__(file_path=file_path, file_type=file_type, info=info)
        self.data = data

    @property
    def data(self) -> bytes:
        """data getter"""
        return self.__data

    @data.setter
    def data(self, data: bytes) -> None:
        """data setter"""
        self.__data = data

    def get_analysis_target(self) -> List[AnalysisTarget]:
        """Return nothing. The class provides only data storage.

        Raise:
            NotImplementedError

        """
        raise NotImplementedError()
