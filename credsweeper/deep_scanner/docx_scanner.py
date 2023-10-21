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
    """Implements pdf scanning"""

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> List[Candidate]:
        """Tries to scan PDF elements recursively and the whole text on page as strings"""
        candidates = []

        try:
            docx_lines = []

            doc = docx.Document(io.BytesIO(data_provider.data))
            for paragraph in doc.paragraphs:
                for line in paragraph.text.splitlines():
                    if line:
                        docx_lines.append(line)

            string_data_provider = StringContentProvider(lines=docx_lines,
                                                         file_path=data_provider.file_path,
                                                         file_type=data_provider.file_type,
                                                         info=f"{data_provider.info}|DOCX")
            pdf_candidates = self.scanner.scan(string_data_provider)
            candidates.extend(pdf_candidates)
        except Exception as docx_exc:
            logger.debug(f"{data_provider.file_path}:{docx_exc}")
        return candidates
