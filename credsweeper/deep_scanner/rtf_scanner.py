import logging
from abc import ABC
from typing import List, Optional

from striprtf import striprtf

from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.string_content_provider import StringContentProvider
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class RtfScanner(AbstractScanner, ABC):
    """Implements squash file system scanning"""

    @staticmethod
    def get_lines(text: str) -> List[str]:
        """Extracts text lines from RTF format"""
        rtf_text = striprtf.rtf_to_text(text)
        lines = Util.split_text(rtf_text)
        return lines

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Scans data as RTF"""
        try:
            string_data_provider = StringContentProvider(lines=RtfScanner.get_lines(data_provider.text),
                                                         file_path=data_provider.file_path,
                                                         file_type=data_provider.file_type,
                                                         info=f"{data_provider.info}|RTF")
            rtf_candidates = self.scanner.scan(string_data_provider)
            return rtf_candidates
        except Exception as rtf_exc:
            logger.error(f"{data_provider.file_path}:{rtf_exc}")
        return None
