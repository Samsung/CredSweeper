import logging
from abc import ABC
from typing import List, Optional

from PySquashfsImage import SquashFsImage

from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.file_path_extractor import FilePathExtractor
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class SquashfsScanner(AbstractScanner, ABC):
    """Implements squash file system scanning"""

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """Squash file system magic and correctness check"""
        if data.startswith(b"hsqs") and b"\x04\x00\x00\x00" == data[28:32]:
            # "Must be a power of two between 4096 (4k) and 1048576 (1 MiB)"
            block_size = int.from_bytes(data[12:16], byteorder="little", signed=False)
            if 0 == 0xFFF & block_size and 4096 <= block_size <= 1048576:
                return True
        return False

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Extracts files one by one from tar archive and launches data_scan"""
        try:
            candidates = []
            with SquashFsImage.from_bytes(data_provider.data) as image:
                for i in image:
                    # skip directory
                    if not i.is_file or i.is_symlink:
                        continue
                    if FilePathExtractor.check_exclude_file(self.config, i.path):
                        continue
                    if 0 > recursive_limit_size - i.size:
                        logger.warning("%s: size %s is over limit %s depth:%s", i.name, i.size, recursive_limit_size,
                                       depth)
                        continue
                    logger.warning("%s:%s", i.path, i.name)
                    hsqs_content_provider = DataContentProvider(data=image.read_file(i.inode),
                                                                file_path=data_provider.file_path,
                                                                file_type=Util.get_type(i.path),
                                                                info=f"{data_provider.info}|HSQS:{i.path}")
                    # Nevertheless, use extracted data size
                    hsqs_candidates = self.recursive_scan(hsqs_content_provider, depth, recursive_limit_size)
                    candidates.extend(hsqs_candidates)
            return candidates
        except Exception as hsqs_exc:
            logger.error("%s:%s", data_provider.file_path, hsqs_exc)
        return None
