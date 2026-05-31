import logging
from abc import ABC

from credsweeper.deep_scanner.pandas_scanner import PandasScanner

logger = logging.getLogger(__name__)


class XlsxScanner(PandasScanner, ABC):
    """Implements xlsx matching"""

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """Assume, ZIP prefix and common office files were checked before"""
        if b"xl/_rels/workbook." in data and b"xl/worksheets/" in data:
            # .xml or .bin inside for .xlsx and .xlsb respectively
            return True
        return False
