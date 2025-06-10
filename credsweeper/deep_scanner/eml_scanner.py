import email
import logging
from abc import ABC
from typing import List, Optional

from credsweeper.credentials.candidate import Candidate
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
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Tries to scan EML with text representation"""
        try:
            candidates: List[Candidate] = []
            msg = email.message_from_bytes(data_provider.data)
            for part in msg.walk():
                content_type = part.get_content_type()
                body = part.get_payload(decode=True)

                if not isinstance(body, (bytes, str)):
                    continue
                if "text/plain" == content_type:
                    eml_text_data_provider = ByteContentProvider(
                        content=(body if isinstance(body, bytes) else body.encode()),
                        file_path=data_provider.file_path,
                        file_type=data_provider.file_type,
                        info=f"{data_provider.info}|EML-TEXT")
                    eml_candidates = self.scanner.scan(eml_text_data_provider)
                    candidates.extend(eml_candidates)
                else:
                    x_data_provider = DataContentProvider(data=(body if isinstance(body, bytes) else body.encode()),
                                                          file_path=data_provider.file_path,
                                                          file_type=data_provider.file_type,
                                                          info=f"{data_provider.info}|EML-DATA")
                    new_limit = recursive_limit_size - len(body)
                    if "text/html" == content_type and x_data_provider.represent_as_html(
                            depth, new_limit, self.scanner.keywords_required_substrings_check):
                        string_data_provider = StringContentProvider(lines=x_data_provider.lines,
                                                                     line_numbers=x_data_provider.line_numbers,
                                                                     file_path=data_provider.file_path,
                                                                     file_type=data_provider.file_type,
                                                                     info=f"{data_provider.info}|EML-HTML")
                        html_candidates = self.scanner.scan(string_data_provider)
                        candidates.extend(html_candidates)
                    elif content_type.startswith("application"):
                        x_candidates = self.recursive_scan(x_data_provider, depth, new_limit)
                        candidates.extend(x_candidates)
                    else:
                        logger.error(f"{data_provider.file_path}:{content_type}:{type(body)} cannot be supported")
            return candidates
        except Exception as eml_exc:
            logger.error(f"{data_provider.file_path}:{eml_exc}")
        return None
