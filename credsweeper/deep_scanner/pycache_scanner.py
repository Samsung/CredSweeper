import logging
import marshal
from abc import ABC
from typing import List, Optional

from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.struct_content_provider import StructContentProvider

logger = logging.getLogger(__name__)


class PycacheScanner(AbstractScanner, ABC):
    """Implements python cache files scanning"""

    MATCHES_SIGNATURES = (
        b"\r\n\x00\x00\x00\x00",
        b"\r\n\x01\x00\x00\x00",
        b"\r\n\x03\x00\x00\x00",
    )

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """Checks header magic for 3 actual variants"""
        if 32 < len(data) and data[2:8] in PycacheScanner.MATCHES_SIGNATURES:
            return True
        return False

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Extracts data from binary"""
        try:
            structure = marshal.loads(data_provider.data[16:])
            pyc_content_provider = StructContentProvider(struct=structure,
                                                         file_path=data_provider.file_path,
                                                         file_type=data_provider.file_type,
                                                         info=f"{data_provider.info}|PYCACHE")
            pyc_candidates = self.structure_scan(pyc_content_provider, depth, recursive_limit_size)
            return pyc_candidates
        except Exception as pyc_exc:
            logger.warning("%s:%s", data_provider.file_path, pyc_exc)
        return None
