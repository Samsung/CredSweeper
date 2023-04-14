import io
import logging
from abc import ABC
from tarfile import TarFile
from typing import List

from credsweeper.credentials import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.file_path_extractor import FilePathExtractor
from credsweeper.utils import Util

logger = logging.getLogger(__name__)


class TarScanner(AbstractScanner, ABC):
    """Implements tar scanning"""

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> List[Candidate]:
        """Extracts files one by one from tar archive and launches data_scan"""
        candidates = []
        try:
            with TarFile(fileobj=io.BytesIO(data_provider.data)) as tf:
                for tfi in tf.getmembers():
                    # skip directory
                    if not tfi.isreg():
                        continue
                    if FilePathExtractor.check_exclude_file(self.config, tfi.name):
                        continue
                    if 0 > recursive_limit_size - tfi.size:
                        logger.error(f"{tfi.name}: size {tfi.size}"
                                     f" is over limit {recursive_limit_size} depth:{depth}")
                        continue
                    with tf.extractfile(tfi) as f:
                        tar_content_provider = DataContentProvider(data=f.read(),
                                                                   file_path=data_provider.file_path,
                                                                   file_type=Util.get_extension(tfi.name),
                                                                   info=f"{data_provider.info}|TAR|{tfi.name}")
                        # Nevertheless, use extracted data size
                        new_limit = recursive_limit_size - len(tar_content_provider.data)
                        tar_candidates = self.recursive_scan(tar_content_provider, depth, new_limit)
                        candidates.extend(tar_candidates)
        except Exception as tar_exc:
            # too many exception types might be produced with broken tar
            logger.error(f"{data_provider.file_path}:{tar_exc}")
        return candidates
