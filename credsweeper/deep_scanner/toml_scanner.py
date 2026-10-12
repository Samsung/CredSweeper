import logging
import tomllib
from abc import ABC
from typing import List, Optional

from credsweeper.common.constants import MAX_LINE_LENGTH
from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.struct_content_provider import StructContentProvider

logger = logging.getLogger(__name__)


class TomlScanner(AbstractScanner, ABC):
    """Implements TOML scanning"""

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """Check if data MAY be in TOML format"""
        equal_pos = data.find(b'=', 0, MAX_LINE_LENGTH)
        if 0 < equal_pos:
            l_square_pos = data.find(b'[', 0, MAX_LINE_LENGTH)
            if 0 <= l_square_pos:
                r_square_pos = data.find(b']', l_square_pos, MAX_LINE_LENGTH)
                if l_square_pos < r_square_pos:
                    return True
        return False

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Tries to scan each row as structure with column name in key"""
        try:
            if toml_data := tomllib.loads(data_provider.text):
                struct_content_provider = StructContentProvider(struct=toml_data,
                                                                file_path=data_provider.file_path,
                                                                file_type=data_provider.file_type,
                                                                info=f"{data_provider.info}|TOML")
                new_limit = recursive_limit_size - len(data_provider.text)
                struct_candidates = self.structure_scan(struct_content_provider, depth, new_limit)
                return struct_candidates
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.debug("%s:%s", data_provider.file_path, exc)
        return None
