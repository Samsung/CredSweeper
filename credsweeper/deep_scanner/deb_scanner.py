import logging
from abc import ABC
from typing import List, Optional

from credsweeper.common.constants import ASCII, MIN_DATA_LEN
from credsweeper.credentials import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider

logger = logging.getLogger(__name__)


class DebScanner(AbstractScanner, ABC):
    """Implements deb (ar) scanning"""

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Extracts data file from .ar (debian) archive and launches data_scan"""
        candidates: Optional[List[Candidate]] = None
        offset = 8  # b"!<arch>\n"
        while offset < len(data_provider.data):
            try:
                file_size_data = data_provider.data[offset + 48:offset + 58]
                file_size = int(file_size_data.decode(ASCII))
                offset += 60
                if file_size < MIN_DATA_LEN:
                    offset += file_size
                    continue
                data = data_provider.data[offset:offset + file_size]
                deb_content_provider = DataContentProvider(data=data,
                                                           file_path=data_provider.file_path,
                                                           file_type=data_provider.file_type,
                                                           info=f"{data_provider.info}|DEB:0x{offset:x}")
                new_limit = recursive_limit_size - file_size
                deb_candidates = self.recursive_scan(deb_content_provider, depth, new_limit)
                if deb_candidates is not None:
                    if candidates:
                        candidates.extend(deb_candidates)
                    else:
                        candidates = deb_candidates
                # data padding = 2
                offset += 1 + file_size if 1 & file_size else file_size
            except Exception as exc:
                logger.error(exc)
        return candidates
