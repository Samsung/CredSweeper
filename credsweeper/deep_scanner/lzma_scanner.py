import io
import logging
import lzma
from abc import ABC
from typing import List, Optional

from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider

logger = logging.getLogger(__name__)


class LzmaScanner(AbstractScanner, ABC):
    """Implements lzma scanning"""

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """According https://en.wikipedia.org/wiki/List_of_file_signatures - lzma also xz"""
        if data.startswith((b"\xFD7zXZ\x00", b"\x5D\x00\x00")):
            return True
        return False

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Extracts data from lzma archive and launches data_scan"""
        try:
            if data_provider.file_type.endswith(".xz"):
                file_type = data_provider.file_type[:-3]
            if data_provider.file_type.endswith(".txz"):
                # .tar.xz synonym
                file_type = data_provider.file_type[:-4]
            elif data_provider.file_type.endswith(".lzma"):
                file_type = data_provider.file_type[:-5]
            else:
                file_type = data_provider.file_type
            with lzma.open(io.BytesIO(data_provider.data), "rb") as f:
                data = AbstractScanner.read_compressed_with_limit(f, recursive_limit_size)
                lzma_content_provider = DataContentProvider(data=data,
                                                            file_path=data_provider.file_path,
                                                            file_type=file_type,
                                                            info=f"{data_provider.info}|LZMA:{len(data)}")
                lzma_candidates = self.recursive_scan(lzma_content_provider, depth, recursive_limit_size)
                return lzma_candidates
        except Exception as lzma_exc:
            logger.warning("%s:%s", data_provider.file_path, lzma_exc)
        return None
