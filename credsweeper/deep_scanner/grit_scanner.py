import logging
import struct
from abc import ABC
from typing import List, Optional, Generator, Tuple

import brotli

from credsweeper.common.constants import MIN_DATA_LEN
from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider

logger = logging.getLogger(__name__)


class GritScanner(AbstractScanner, ABC):
    """Implements pak files from grit scanning"""

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """Versions 4,5"""
        if data.startswith((b"\x04\x00\x00\x00", b"\x05\x00\x00\x00")):
            return True
        return False

    @staticmethod
    def walk_pak(data: bytes, limit: int) -> Generator[Tuple[int, int, bytes], None, None]:
        """Processes sequence of PAK archive and yields offset, resource id and data"""
        version = struct.unpack_from("<I", data, offset=0)[0]
        if 4 == version:
            resource_count, _encoding = struct.unpack_from('<IB', data, offset=4)
            header_size = 9
        elif 5 == version:
            _encoding, resource_count, _alias_count = struct.unpack_from('<BxxxHH', data, offset=4)
            header_size = 12
        else:
            raise ValueError(f"Unsupported version {repr(data[:4])}")
        resource_id, resource_offset = struct.unpack_from('<HI', data, offset=header_size)
        for n in range(1, resource_count + 1):
            next_resource_id, next_offset = struct.unpack_from('<HI', data, offset=header_size + 6 * n)
            if 0 < resource_offset < next_offset <= len(data) and MIN_DATA_LEN < next_offset - resource_offset:
                payload = data[resource_offset:next_offset]
                if payload.startswith(b"\x1e\x9b"):
                    # brotli compression marker for grit
                    size_lo, size_hi = struct.unpack_from('<IH', payload, offset=2)
                    size = size_lo | size_hi << 32
                    if size < limit:
                        try:
                            payload = brotli.decompress(payload[8:])
                        except Exception as e:
                            logger.error("%s %d %d", e, resource_offset, resource_id)
                            payload = None
                    else:
                        logger.warning("Skip oversized %d", size)
                        payload = None
                if isinstance(payload, bytes) and MIN_DATA_LEN < len(payload):
                    yield resource_offset, resource_id, payload
            else:
                logger.debug("Skip %d:%d %d", resource_offset, next_offset, len(data))
            resource_id = next_resource_id
            resource_offset = next_offset

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Extracts data file from .pak and launches data_scan"""
        try:
            candidates: List[Candidate] = []
            for offset, _id, data in GritScanner.walk_pak(data_provider.data, recursive_limit_size):
                pak_content_provider = DataContentProvider(data=data,
                                                           file_path=data_provider.file_path,
                                                           file_type=data_provider.file_type,
                                                           info=f"{data_provider.info}|GRIT:0x{offset:x}:{_id}")
                pak_candidates = self.recursive_scan(pak_content_provider, depth, recursive_limit_size)
                candidates.extend(pak_candidates)
            return candidates
        except Exception as exc:
            logger.warning(exc)
        return None
