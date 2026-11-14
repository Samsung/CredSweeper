import io
import logging
from abc import ABC
from typing import List, Optional, Generator, Tuple
from zipfile import ZipFile, BadZipFile

from credsweeper.config.config import Config
from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.file_path_extractor import FilePathExtractor
from credsweeper.logger import TRACE
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
        except Exception as exc:  # pylint: disable=broad-exception-caught
            # too many exception types might be produced with broken zip
            logger.warning("%s:%s", type(exc), exc)
        return -1

    @staticmethod
    def walk_zip(
            stream: io.BytesIO,  #
            limit: int = -1,  #
            config: Config | None = None,  #
    ) -> Generator[Tuple[str, bytes], None, None]:
        """Extracts valuable data from ZIP archive with limit check and config defined filter"""
        with ZipFile(stream) as zf:
            for zfl in zf.infolist():
                if zfl.is_dir():
                    # skip directory anyway
                    continue
                if limit < zfl.file_size:
                    logger.warning("%s: size %s is over limit %s", zfl.filename, zfl.file_size, limit)
                    continue
                if config and FilePathExtractor.check_exclude_file(config, zfl.filename):
                    logger.log(TRACE, "Skip %s %s", zfl.filename, zfl.file_size)
                    continue
                with zf.open(zfl) as f:
                    yield zfl.filename, f.read()

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Extracts files one by one from zip archives and launches data_scan"""
        try:
            candidates = []
            recursive_limit_size -= len(data_provider.data)
            stream = io.BytesIO(data_provider.data)
            for filename, filedata in ZipScanner.walk_zip(stream, recursive_limit_size, self.config):
                zip_content_provider = DataContentProvider(data=filedata,
                                                           file_path=data_provider.file_path,
                                                           file_type=Util.get_type(filename),
                                                           info=f"{data_provider.info}|ZIP:{filename}")
                zip_candidates = self.recursive_scan(zip_content_provider, depth, recursive_limit_size)
                candidates.extend(zip_candidates)
            return candidates
        except BadZipFile as zip_exc:
            logger.log(TRACE, "%s %s", zip_exc, data_provider.descriptor)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            # too many exception types might be produced with broken zip
            logger.warning("%s:%s:%s", type(exc), exc, data_provider.descriptor)
        return None
