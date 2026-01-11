import logging
import zlib
from abc import ABC
from typing import List, Optional

from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider

logger = logging.getLogger(__name__)


class ZlibScanner(AbstractScanner, ABC):
    """Implements zlib data inflate and scan"""

    @staticmethod
    def match(data: bytes) -> bool:
        """Returns True if data looks like deflated data with zlib"""
        if 6 < len(data):
            cmf = data[0]
            flg = data[1]
            if 8 == (0xF & cmf) and 7 >= (cmf >> 4) and 0 == ((cmf << 8) | flg) % 31 and 0 == (0x20 & flg):
                if 0x3 != (data[2] >> 1):
                    # the last check of impossible bits
                    return True
        return False

    @staticmethod
    def decompress(limit: int, data: bytes) -> bytes:
        """Returns decompressed data by chunks with a limit or exception in unusual cases"""
        zlib_obj = zlib.decompressobj()
        result = zlib_obj.decompress(data, max_length=limit)
        if zlib_obj.unconsumed_tail:
            raise ValueError(f"Limit exceeds for {len(zlib_obj.unconsumed_tail)}")
        if not zlib_obj.eof:
            raise ValueError("Truncated zlib stream")
        if zlib_obj.unused_data:
            raise ValueError(f"Unused data {len(zlib_obj.unused_data)}")
        return result

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Inflate data from zlib compressed and launches data_scan"""
        try:
            decompressed = ZlibScanner.decompress(recursive_limit_size, data_provider.data)
            zlib_content_provider = DataContentProvider(data=decompressed,
                                                        file_path=data_provider.file_path,
                                                        file_type=data_provider.file_type,
                                                        info=f"{data_provider.info}|ZLIB")
            new_limit = recursive_limit_size - len(decompressed)
            zlib_candidates = self.recursive_scan(zlib_content_provider, depth, new_limit)
            return zlib_candidates
        except Exception as zlib_exc:
            logger.error(f"{data_provider.file_path}:{zlib_exc}")
        return None
