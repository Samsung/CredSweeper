import logging
from abc import ABC
from typing import List, Optional, Tuple

from credsweeper.common.constants import MIN_DATA_LEN
from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.string_content_provider import StringContentProvider

logger = logging.getLogger(__name__)


class StringsScanner(AbstractScanner, ABC):
    """Implements known binary file scanning with ASCII strings representations"""

    @staticmethod
    def get_strings(data: bytes) -> List[Tuple[str, int]]:
        """Processes binary to found ASCII strings. Use offset instead line number."""
        strings = []
        offset = 0
        line = ''
        for n, x in enumerate(data):
            if 0x09 == x or 0x20 <= x <= 0x7E:
                # TAB, SPACE and visible ASCII symbols
                if not offset:
                    # for line number
                    offset = n
                line += chr(x)
            elif MIN_DATA_LEN <= len(line):
                strings.append((line, offset))
                offset = 0
                line = ''
        if MIN_DATA_LEN <= len(line):
            strings.append((line, offset))
        return strings

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Extracts data file from .ar (debian) archive and launches data_scan"""

        if strings := StringsScanner.get_strings(data_provider.data):
            string_data_provider = StringContentProvider(lines=[x[0] for x in strings],
                                                         line_numbers=[x[1] for x in strings],
                                                         file_path=data_provider.file_path,
                                                         file_type=data_provider.file_type,
                                                         info=f"{data_provider.info}|STRINGS")
            return self.scanner.scan(string_data_provider)
        return None if strings is None else []
