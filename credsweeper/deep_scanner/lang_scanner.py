import logging
from abc import ABC
from typing import List, Optional

from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.struct_content_provider import StructContentProvider

logger = logging.getLogger(__name__)


class LangScanner(AbstractScanner, ABC):
    """Implements scanning of data if it is a script of some markup language"""

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """Applied in represent_as_structure"""
        return True

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Tries to represent data as markup language and scan as structure"""
        if result := data_provider.represent_as_structure():
            struct_data_provider = StructContentProvider(struct=data_provider.structure,
                                                         file_path=data_provider.file_path,
                                                         file_type=data_provider.file_type,
                                                         info=f"{data_provider.info}|STRUCT")
            new_limit = recursive_limit_size - len(data_provider.data)
            return self.structure_scan(struct_data_provider, depth, new_limit)
        return None if result is None else []
