import bz2
import io
import logging
from abc import ABC
from typing import List, Optional

from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider

logger = logging.getLogger(__name__)


class Bzip2Scanner(AbstractScanner, ABC):
    """Implements bzip2 scanning"""

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """According https://en.wikipedia.org/wiki/Bzip2"""
        if data.startswith(b"\x42\x5A\x68") and 10 <= len(data) \
                and 0x31 <= data[3] <= 0x39 \
                and 4 == data.find(b"\x31\x41\x59\x26\x53\x59", 4, 10):
            return True
        return False

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Extracts data from bzip2 archive and launches data_scan"""
        try:
            if data_provider.file_type.endswith(".bz2"):
                file_type = data_provider.file_type[:-4]
            else:
                file_type = data_provider.file_type
            with bz2.open(io.BytesIO(data_provider.data), "rb") as f:
                data = AbstractScanner.read_compressed_with_limit(f, recursive_limit_size)
                bzip2_content_provider = DataContentProvider(data=data,
                                                             file_path=data_provider.file_path,
                                                             file_type=file_type,
                                                             info=f"{data_provider.info}|BZIP2:{len(data)}")
                bzip2_candidates = self.recursive_scan(bzip2_content_provider, depth, recursive_limit_size)
                return bzip2_candidates
        except AbstractScanner.LimitError as bzip2_limit_exc:
            logger.warning("%s %s", data_provider.descriptor, bzip2_limit_exc)
            return []
        except Exception as bzip2_exc:
            logger.warning("%s:%s", data_provider.descriptor, bzip2_exc)
        return None
