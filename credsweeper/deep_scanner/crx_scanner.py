import logging
import struct
from abc import ABC
from typing import List, Optional

from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider

logger = logging.getLogger(__name__)


class CrxScanner(AbstractScanner, ABC):
    """Implements CRX files scanning with cut-off prefix"""

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """Returns True if prefix match"""
        if data.startswith((b"Cr24\x02\x00\x00\x00", b"Cr24\x03\x00\x00\x00")) and 32 < len(data):
            return True
        return False

    @staticmethod
    def zip_extract(data: bytes) -> bytes:
        """Extracts zip payload after signature block"""
        pubkey_length = struct.unpack("<I", data[8:12])
        signature_length = struct.unpack("<I", data[12:16])
        zip_offset = 16 + pubkey_length[0] + signature_length[0]
        return data[zip_offset:]

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Tries cut-off header and use ZIP payload"""
        try:
            zip_data = CrxScanner.zip_extract(data_provider.data)
            zip_content_provider = DataContentProvider(data=zip_data,
                                                       file_path=data_provider.file_path,
                                                       file_type=data_provider.file_type,
                                                       info=f"{data_provider.info}|CRX")
            crx_candidates = self.recursive_scan(zip_content_provider, depth, recursive_limit_size)
            return crx_candidates
        except Exception as exc:
            logger.warning(exc)
        return None
