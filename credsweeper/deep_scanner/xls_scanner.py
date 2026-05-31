import logging
from abc import ABC

from credsweeper.deep_scanner.pandas_scanner import PandasScanner

logger = logging.getLogger(__name__)


class XlsScanner(PandasScanner, ABC):
    """Implements xls matching"""

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """According https://en.wikipedia.org/wiki/List_of_file_signatures"""
        if data.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
            # Compound File Binary Format: doc, xls, ppt, msi, msg
            return True
        return False
