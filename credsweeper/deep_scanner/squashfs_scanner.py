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
                    logger.warning(f"{i.path}")
                    if FilePathExtractor.check_exclude_file(self.config, i.path):
                        continue
                    if 0 > recursive_limit_size - i.size:
                        logger.error(f"{i.name}: size {i.size}"
                                     f" is over limit {recursive_limit_size} depth:{depth}")
                        continue
                    logger.warning(f"{i.path} {i.name}")
                    hsqs_content_provider = DataContentProvider(data=image.read_file(i.inode),
                                                                file_path=i.path,
                                                                file_type=Util.get_extension(i.path),
                                                                info=f"{data_provider.info}|HSQS:{i.path}")
                    # Nevertheless, use extracted data size
                    new_limit = recursive_limit_size - len(hsqs_content_provider.data)
                    logger.info(f"{i.name}: size {len(hsqs_content_provider.data)}")
                    hsqs_candidates = self.recursive_scan(hsqs_content_provider, depth, new_limit)
                    candidates.extend(hsqs_candidates)
            return candidates
        except Exception as hsqs_exc:
            logger.error(f"{data_provider.file_path}:{hsqs_exc}")
        return None
