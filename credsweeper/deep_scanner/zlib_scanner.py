import logging
import zlib
from abc import ABC
from typing import List, Optional

from credsweeper.common.constants import MIN_DATA_LEN
from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider

logger = logging.getLogger(__name__)


class ZlibScanner(AbstractScanner, ABC):
    """Implements lzib data inflate and scan"""

    @staticmethod
    def possible_zlib(data: bytes) -> bool:
        """Returns True if data looks like deflated data with zlib"""
        if 6 < len(data):
            cmf = data[0]
            flg = data[1]
            if 8 == (0xF & cmf) and 7 >= (cmf >> 4) and 0 == ((cmf << 8) | flg) % 31 and 0 == (0x20 & flg):
                return bool(0x3 != (data[2] >> 1))
        return False

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Inflate data from lzib compressed and launches data_scan"""
        try:
            zlib_content_provider = DataContentProvider(data=zlib.decompress(data_provider.data),
                                                        file_path=data_provider.file_path,
                                                        file_type=data_provider.file_type,
                                                        info=f"{data_provider.info}|ZLIB")
            new_limit = recursive_limit_size - len(zlib_content_provider.data)
            zlib_candidates = self.recursive_scan(zlib_content_provider, depth, new_limit)
            return zlib_candidates
        except Exception as lzib_exc:
            logger.error(f"{data_provider.file_path}:{lzib_exc}")
        return None
