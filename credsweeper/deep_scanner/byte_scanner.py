import logging
from abc import ABC
from typing import List, Optional

from credsweeper.credentials.candidate import Candidate
from credsweeper.file_handler.byte_content_provider import ByteContentProvider
from credsweeper.file_handler.data_content_provider import DataContentProvider
from .abstract_scanner import AbstractScanner

logger = logging.getLogger(__name__)


class ByteScanner(AbstractScanner, ABC):
    """Implements plain data scanning"""

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Tries to represent data as plain text with splitting by lines and scan as text lines"""
        byte_content_provider = ByteContentProvider(content=data_provider.data,
                                                    file_path=data_provider.file_path,
                                                    file_type=data_provider.file_type,
                                                    info=f"{data_provider.info}|RAW")
        return self.scanner.scan(byte_content_provider)
