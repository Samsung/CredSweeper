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
                        logger.error(f"{zfl.filename}: size {zfl.file_size}"
                                     f" is over limit {recursive_limit_size} depth:{depth}")
                        continue
                    with zf.open(zfl) as f:
                        zip_content_provider = DataContentProvider(data=f.read(),
                                                                   file_path=data_provider.file_path,
                                                                   file_type=Util.get_extension(zfl.filename),
                                                                   info=f"{data_provider.info}|ZIP:{zfl.filename}")
                        # nevertheless use extracted data size
                        new_limit = recursive_limit_size - len(zip_content_provider.data)
                        zip_candidates = self.recursive_scan(zip_content_provider, depth, new_limit)
                        candidates.extend(zip_candidates)
            return candidates
        except Exception as zip_exc:
            # too many exception types might be produced with broken zip
            logger.error(f"{data_provider.file_path}:{zip_exc}")
        return None
