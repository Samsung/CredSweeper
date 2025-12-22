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
    def get_enumerated_lines(data: bytes) -> List[Tuple[int, str]]:
        """Processes binary to found ASCII strings. Use offset instead line number."""
        enumerated_lines = []
        offset = -1
        line_items = []
        for n, x in enumerate(data):
            if 0x09 == x or 0x20 <= x <= 0x7E:
                # TAB, SPACE and visible ASCII symbols
                if 0 > offset:
                    # use start of string as line number
                    offset = n
                line_items.append(chr(x))
                continue
            if MIN_DATA_LEN <= len(line_items):
                # add valuable lines only
                enumerated_lines.append((offset, ''.join(line_items)))
            offset = -1
            line_items.clear()
        if MIN_DATA_LEN <= len(line_items):
            enumerated_lines.append((offset, ''.join(line_items)))
        return enumerated_lines

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Extracts data file from .ar (debian) archive and launches data_scan"""

        if strings := StringsScanner.get_enumerated_lines(data_provider.data):
            string_data_provider = StringContentProvider(lines=[x[1] for x in strings],
                                                         line_numbers=[x[0] for x in strings],
                                                         file_path=data_provider.file_path,
                                                         file_type=data_provider.file_type,
                                                         info=f"{data_provider.info}|STRINGS")
            return self.scanner.scan(string_data_provider)
        return None if strings is None else []
