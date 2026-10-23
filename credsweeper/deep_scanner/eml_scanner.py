import email
import logging
from abc import ABC
from typing import List, Optional

from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.byte_content_provider import ByteContentProvider
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.logger import TRACE

logger = logging.getLogger(__name__)


class EmlScanner(AbstractScanner, ABC):
    """Implements eml scanning"""

    shelf = True

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """According to https://datatracker.ietf.org/doc/html/rfc822 lookup the fields: Date, From, To or Subject"""
        if (b"\nDate:" in data or data.startswith(b"Date:")) \
                and (b"\nFrom:" in data or data.startswith(b"From:")) \
                and (b"\nTo:" in data or data.startswith(b"To:")) \
                and (b"\nSubject:" in data or data.startswith(b"Subject:")):
            return True
        return False

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
                    logger.log(TRACE, "Skip unsupported body %s %s", type(body), data_provider.descriptor)
                    continue
                if "text/plain" == content_type or content_type.startswith("message/"):
                    # avoid
                    eml_text_data_provider = ByteContentProvider(
                        content=(body if isinstance(body, bytes) else body.encode()),
                        file_path=data_provider.file_path,
                        file_type=data_provider.file_type,
                        info=f"{data_provider.info}|EML[{content_type}]")
                    eml_candidates = self.scanner.scan(eml_text_data_provider)
                    candidates.extend(eml_candidates)
                elif content_type.startswith(("text/", "application/")):
                    eml_part_data_provider = DataContentProvider(
                        data=(body if isinstance(body, bytes) else body.encode()),
                        file_path=data_provider.file_path,
                        file_type=data_provider.file_type,
                        info=f"{data_provider.info}|EML[{content_type}]")
                    new_limit = recursive_limit_size - len(body)
                    part_candidates = self.recursive_scan(eml_part_data_provider, depth, new_limit)
                    candidates.extend(part_candidates)
                else:
                    logger.log(TRACE, "Skip unsupported content type %s %s", type(body), data_provider.descriptor)
                    continue

            return candidates
        except Exception as exc:  # pylint: disable=broad-exception-caught
            # fallback
            logger.warning("%s:%s:%s", type(exc), exc, data_provider.descriptor)
        return None
