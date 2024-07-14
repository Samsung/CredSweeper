import bz2
import logging
from abc import ABC
from pathlib import Path
from typing import List

from credsweeper.credentials import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.utils import Util

logger = logging.getLogger(__name__)


class Bzip2Scanner(AbstractScanner, ABC):
    """Implements bzip2 scanning"""

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> List[Candidate]:
        """Extracts data from bzip2 archive and launches data_scan"""
        candidates = []
        try:
            file_path = Path(data_provider.file_path)
            new_path = file_path.as_posix()
            if ".bz2" == file_path.suffix:
                new_path = new_path[:-4]
            bzip2_content_provider = DataContentProvider(data=bz2.decompress(data_provider.data),
                                                         file_path=new_path,
                                                         file_type=Util.get_extension(new_path),
                                                         info=f"{data_provider.info}|BZIP2|{new_path}")
            new_limit = recursive_limit_size - len(bzip2_content_provider.data)
            bzip2_candidates = self.recursive_scan(bzip2_content_provider, depth, new_limit)
            candidates.extend(bzip2_candidates)
        except Exception as bzip2_exc:
            logger.error(f"{data_provider.file_path}:{bzip2_exc}")
        return candidates
