import email
import logging
from abc import ABC
from typing import List

from credsweeper.credentials import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.byte_content_provider import ByteContentProvider
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.string_content_provider import StringContentProvider

logger = logging.getLogger(__name__)


class EmlScanner(AbstractScanner, ABC):
    """Implements eml scanning"""

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> List[Candidate]:
        """Tries to scan EML with text representation"""
        candidates = []

        try:
            msg = email.message_from_bytes(data_provider.data)
            for part in msg.walk():
                content_type = part.get_content_type()
                body = part.get_payload(decode=True)

                if "text/plain" == content_type:
                    eml_text_data_provider = ByteContentProvider(content=body,
                                                                 file_path=data_provider.file_path,
                                                                 file_type=data_provider.file_type,
                                                                 info=f"{data_provider.info}|EML-TEXT")
                    eml_candidates = self.scanner.scan(eml_text_data_provider)
                    candidates.extend(eml_candidates)
                elif "text/html" == content_type:
                    html_data_provider = DataContentProvider(data=body)
                    if html_data_provider.represent_as_html(depth, recursive_limit_size,
                                                            self.scanner.keywords_required_substrings_check):
                        string_data_provider = StringContentProvider(lines=html_data_provider.lines,
                                                                     line_numbers=html_data_provider.line_numbers,
                                                                     file_path=data_provider.file_path,
                                                                     file_type=data_provider.file_type,
                                                                     info=f"{data_provider.info}|EML-HTML")
                        html_candidates = self.scanner.scan(string_data_provider)
                        candidates.extend(html_candidates)
        except Exception as eml_exc:
            logger.error(f"{data_provider.file_path}:{eml_exc}")
        return candidates
