import io
import logging
from abc import ABC
from typing import List

import docx

from credsweeper.credentials import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.string_content_provider import StringContentProvider

logger = logging.getLogger(__name__)


class DocxScanner(AbstractScanner, ABC):
    """Implements docx scanning"""

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> List[Candidate]:
        """Tries to scan DOCX text with splitting by lines"""
        candidates: List[Candidate] = []

        try:
            docx_lines: List[str] = []

            doc = docx.Document(io.BytesIO(data_provider.data))
            for paragraph in doc.paragraphs:
                for line in paragraph.text.splitlines():
                    if line:
                        docx_lines.append(line)

            string_data_provider = StringContentProvider(lines=docx_lines,
                                                         file_path=data_provider.file_path,
                                                         file_type=data_provider.file_type,
                                                         info=f"{data_provider.info}|DOCX")
            candidates = self.scanner.scan(string_data_provider)
        except Exception as docx_exc:
            logger.debug(f"{data_provider.file_path}:{docx_exc}")
        return candidates
