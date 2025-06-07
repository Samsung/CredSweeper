import io
import logging
from abc import ABC
from typing import List, Optional

from pdfminer.high_level import extract_pages
from pdfminer.layout import LAParams, LTText, LTItem

from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider, MIN_DATA_LEN
from credsweeper.file_handler.string_content_provider import StringContentProvider

logger = logging.getLogger(__name__)


class PdfScanner(AbstractScanner, ABC):
    """Implements pdf scanning"""

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Tries to scan PDF elements recursively and the whole text on page as strings"""
        # PyPDF2 - https://github.com/py-pdf/pypdf/issues/1328 text in table is merged without spaces
        # pdfminer.six - splits text in table to many lines. Allows to walk through elements
        try:
            candidates = []
            for page in extract_pages(io.BytesIO(data_provider.data), laparams=LAParams()):
                for element in page:
                    if isinstance(element, LTText):
                        element_text = element.get_text().strip()
                        if 0 < depth and element_text:
                            if MIN_DATA_LEN < len(element_text):
                                pdf_content_provider = DataContentProvider(
                                    data=element_text.encode(),
                                    file_path=data_provider.file_path,
                                    file_type=data_provider.file_type,
                                    info=f"{data_provider.info}|PDF:{page.pageid}")
                                new_limit = recursive_limit_size - len(pdf_content_provider.data)
                                element_candidates = self.recursive_scan(pdf_content_provider, depth, new_limit)
                                candidates.extend(element_candidates)
                        else:
                            string_data_provider = StringContentProvider(lines=[element_text],
                                                                         file_path=data_provider.file_path,
                                                                         file_type=data_provider.file_type,
                                                                         info=f"{data_provider.info}|PDF:{page.pageid}")
                            pdf_candidates = self.scanner.scan(string_data_provider)
                            candidates.extend(pdf_candidates)
                    elif isinstance(element, LTItem):
                        pass
                    else:
                        logger.error(f"Unsupported {element}")
            return candidates
        except Exception as pdf_exc:
            logger.error(f"{data_provider.file_path}:{pdf_exc}")
        return None
