import logging
from typing import List, Optional

from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.content_provider import ContentProvider

logger = logging.getLogger(__name__)


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
        self.decoded: Optional[bytes] = None

    @property
    def data(self) -> bytes:
        """data getter"""
        return self.__data

    @data.setter
    def data(self, data: bytes) -> None:
        """data setter"""
        self.__data = data

    def is_encoded(self) -> bool:
        """Encodes data from base64. Stores result in decoded

        Return:
             True if the data correctly parsed and verified

        """
        if len(self.data) < 12 or (b"=" in self.data and b"=" != self.data[-1]):
            logger.debug("Weak data to decode from base64: %s", self.data)
        try:
            self.decoded = base64.b64decode(  #
                self.data.decode(encoding='ascii', errors='strict').  #
                translate(str.maketrans('', '', string.whitespace)),  #
                validate=True)  #
        except Exception as exc:
            logger.debug("Cannot decoded as base64:%s %s", exc, self.data)
            return False
        return self.decoded is not None and 0 < len(self.decoded)

    def get_analysis_target(self) -> List[AnalysisTarget]:
        """Return nothing. The class provides only data storage.

        Raise:
            NotImplementedError

        """
        raise NotImplementedError()
