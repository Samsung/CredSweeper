import logging
import struct
from abc import ABC
from typing import List, Optional, Generator, Tuple

from credsweeper.common.constants import MIN_DATA_LEN, UTF_8
from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class DebScanner(AbstractScanner, ABC):
    """Implements deb (ar) scanning"""

    __header_size = 60

    @staticmethod
    def walk_deb(data: bytes) -> Generator[Tuple[int, str, bytes], None, None]:
        """Processes sequence of DEB archive and yields offset, name and data"""
        offset = 8  # b"!<arch>\n"
        data_limit = len(data) - DebScanner.__header_size
        while offset <= data_limit:
            _data = data[offset:offset + DebScanner.__header_size]
            offset += DebScanner.__header_size
            # basic header structure
            _name, _, _size, __ = struct.unpack('16s32s10s2s', _data)
            file_size = int(_size)
            if MIN_DATA_LEN < file_size <= len(data) - offset:
                _data = data[offset:offset + file_size]
                yield offset, _name.decode(encoding=UTF_8).strip().rstrip('/'), _data
            offset += file_size if 0 == 1 & file_size else file_size + 1

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Extracts data file from .ar (debian) archive and launches data_scan"""
        try:
            candidates: List[Candidate] = []
            for offset, name, data in DebScanner.walk_deb(data_provider.data):
                deb_content_provider = DataContentProvider(data=data,
                                                           file_path=f"{data_provider.file_path}/{name}",
                                                           file_type=Util.get_extension(name),
                                                           info=f"{data_provider.info}|DEB:0x{offset:x}")
                new_limit = recursive_limit_size - len(data)
                deb_candidates = self.recursive_scan(deb_content_provider, depth, new_limit)
                candidates.extend(deb_candidates)
            return candidates
        except Exception as exc:
            logger.error(exc)
        return None
