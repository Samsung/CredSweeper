import io
import logging
from abc import ABC
from typing import List, Optional
from zipfile import ZipFile

from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.file_path_extractor import FilePathExtractor
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class ZipScanner(AbstractScanner, ABC):
    """Implements zip scanning"""

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """According https://en.wikipedia.org/wiki/List_of_file_signatures"""
        if data.startswith(b"PK") and 4 <= len(data):
            if 0x03 == data[2] and 0x04 == data[3]:
                # normal PK
                return True
            if 0x05 == data[2] and 0x06 == data[3]:
                # empty archive - no sense to scan in other scanners, so let it be a zip
                return True
            if 0x07 == data[2] and 0x08 == data[3]:
                # spanned archive - NOT SUPPORTED
                return False
        return False

    @staticmethod
    def get_size(data: bytes | bytearray) -> int:
        """Evaluate extracted archive size

        Returns: size of data or -1 in failure case"""
        try:
            result = 0
            with ZipFile(io.BytesIO(data)) as zf:
                for zfl in zf.infolist():
                    # file names use memory too
                    result += len(zfl.filename)
                    if zfl.is_dir():
                        # skip directory
                        continue
                    # effective size
                    result += zfl.file_size
            return result
        except Exception as zip_exc:
            # too many exception types might be produced with broken zip
            logger.warning("%s", zip_exc)
        return -1

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Extracts files one by one from zip archives and launches data_scan"""
        try:
            candidates = []
            with ZipFile(io.BytesIO(data_provider.data)) as zf:
                for zfl in zf.infolist():
                    # skip directory
                    if zfl.is_dir():
                        continue
                    if FilePathExtractor.check_exclude_file(self.config, zfl.filename):
                        continue
                    if 0 > recursive_limit_size - zfl.file_size:
                        logger.warning("%s: size %s is over limit %s depth:%s", zfl.filename, zfl.file_size,
                                       recursive_limit_size, depth)
                        continue
                    with zf.open(zfl) as f:
                        zip_content_provider = DataContentProvider(data=f.read(),
                                                                   file_path=data_provider.file_path,
                                                                   file_type=Util.get_type(zfl.filename),
                                                                   info=f"{data_provider.info}|ZIP:{zfl.filename}")
                        zip_candidates = self.recursive_scan(zip_content_provider, depth, recursive_limit_size)
                        candidates.extend(zip_candidates)
            return candidates
        except Exception as zip_exc:
            # too many exception types might be produced with broken zip
            logger.warning("%s:%s", data_provider.file_path, zip_exc)
        return None
