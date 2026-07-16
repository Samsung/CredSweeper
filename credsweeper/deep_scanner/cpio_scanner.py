import io
import logging
import struct
from abc import ABC
from typing import List, Optional, Generator, Tuple

from rpmfile.cpiofile import CpioMemberNew, CpioFile

from credsweeper.common.constants import MIN_DATA_LEN, UTF_8
from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class CpioScanner(AbstractScanner, ABC):
    """Implements cpio (ar) scanning"""

    __header_size = 60

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """According https://en.wikipedia.org/wiki/List_of_file_signatures"""
        if data.startswith((b"\x71\xc7", b"\xc7\x71", b"070707", b"070701", b"070702")) and data.endswith(b"\0\0"):
            return True
        return False

    @staticmethod
    def walk_cpio(data: bytes) -> Generator[Tuple[str, bytes], None, None]:
        """Processes sequence of cpio archive and yields offset, name and data"""
        for member in CpioFile()._open(fileobj=io.BytesIO(data)).members:
            yield member.name.decode(encoding=UTF_8).strip().rstrip('/'), member.content

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Extracts data file from .ar (cpioian) archive and launches data_scan"""
        try:
            candidates: List[Candidate] = []
            for name, data in CpioScanner.walk_cpio(data_provider.data):
                cpio_content_provider = DataContentProvider(data=data,
                                                            file_path=data_provider.file_path,
                                                            file_type=Util.get_type(name),
                                                            info=f"{data_provider.info}|cpio:{name}")
                cpio_candidates = self.recursive_scan(cpio_content_provider, depth, recursive_limit_size)
                candidates.extend(cpio_candidates)
            return candidates
        except Exception as exc:
            logger.warning(exc)
        return None
