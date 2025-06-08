import logging
from abc import ABC
from typing import List, Optional

from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.string_content_provider import StringContentProvider

logger = logging.getLogger(__name__)


class XmlScanner(AbstractScanner, ABC):
    """Realises xml scanning"""

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Tries to represent data as xml text and scan as text lines"""
        if result := data_provider.represent_as_xml():
            string_data_provider = StringContentProvider(lines=data_provider.lines,
                                                         line_numbers=data_provider.line_numbers,
                                                         file_path=data_provider.file_path,
                                                         file_type=data_provider.file_type,
                                                         info=f"{data_provider.info}|XML")
            return self.scanner.scan(string_data_provider)
        return None if result is None else []
