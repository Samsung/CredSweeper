import io
import logging
from abc import ABC
from typing import List

from pptx import Presentation

from credsweeper.credentials import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.string_content_provider import StringContentProvider

logger = logging.getLogger(__name__)


class PptxScanner(AbstractScanner, ABC):
    """Implements pptx scanning"""

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> List[Candidate]:
        """Tries to scan pptx text elements for all slides"""
        candidates = []
        try:
            pptx_lines = []
            presentation = Presentation(io.BytesIO(data_provider.data))
            for slide in presentation.slides:
                for shape in slide.shapes:
                    if shape.has_text_frame:
                        for paragraph in shape.text_frame.paragraphs:
                            pptx_lines.append(paragraph.text)
            string_data_provider = StringContentProvider(lines=pptx_lines,
                                                         file_path=data_provider.file_path,
                                                         file_type=data_provider.file_type,
                                                         info=f"{data_provider.info}|pptx")
            pptx_candidates = self.scanner.scan(string_data_provider)
            candidates.extend(pptx_candidates)
        except Exception as pptx_exc:
            logger.error(f"{data_provider.file_path}:{pptx_exc}")
        return candidates
