import logging
from abc import ABC
from typing import List, Optional

from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.string_content_provider import StringContentProvider

logger = logging.getLogger(__name__)


class TextScanner(AbstractScanner, ABC):
    """Regular text scanner with lines splitting"""

    shelf = True

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """Match logic in data_scan"""
        return True

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Scan binary files for well encoded text and split it into strings"""
        string_data_provider = StringContentProvider(lines=data_provider.lines,
                                                     file_path=data_provider.file_path,
                                                     file_type=data_provider.file_type,
                                                     info=f"{data_provider.info}|TEXT")
        return self.scanner.scan(string_data_provider)
