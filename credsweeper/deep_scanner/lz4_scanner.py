import logging
from abc import ABC
from typing import List, Optional

import lz4.frame

from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.logger import TRACE

logger = logging.getLogger(__name__)


class LZ4Scanner(AbstractScanner, ABC):
    """Implements LZ4 data inflate and scan"""

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """Returns True if data looks like deflated data with lz4"""
        if data.startswith(b"\x04\x22\x4D\x18"):
            return True
        return False

    @staticmethod
    def decompress(limit: int, data: bytes) -> bytes:
        """Decompress lz4 compressed data with limit"""
        fd = lz4.frame.LZ4FrameDecompressor()
        out = bytearray()
        budget = limit
        pos = 0
        while not fd.eof:
            if fd.needs_input:
                chunk = data[pos:pos + 65536]
                if not chunk:
                    raise ValueError(f"Incomplete data at 0x{pos:x}")
                pos += len(chunk)
            else:
                chunk = b''

            want = min(65536, budget)
            out += fd.decompress(chunk, max_length=want)
            budget = limit - len(out)
            if budget < 0:
                logger.warning("Decompression limit exceeded %s", limit)
                return b''

        return bytes(out)

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Inflate data from lz4 compressed and launches recursive_scan"""
        try:
            if decompressed := LZ4Scanner.decompress(recursive_limit_size, data_provider.data):
                lz4_content_provider = DataContentProvider(data=decompressed,
                                                           file_path=data_provider.file_path,
                                                           file_type=data_provider.file_type,
                                                           info=f"{data_provider.info}|LZ4:{len(decompressed)}")
                lz4_candidates = self.recursive_scan(lz4_content_provider, depth, recursive_limit_size)
                return lz4_candidates
            return []
        except Exception as exc:  # pylint: disable=broad-exception-caught
            # fallback
            logger.log(TRACE, "%s:%s:%s", type(exc), exc, data_provider.descriptor)
        return None
