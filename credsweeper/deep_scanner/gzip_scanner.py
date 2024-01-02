import gzip
import io
import logging
from abc import ABC
from typing import List

from credsweeper.credentials import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.utils import Util

logger = logging.getLogger(__name__)


class GzipScanner(AbstractScanner, ABC):
    """Realises gzip scanning"""

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> List[Candidate]:
        """Extracts data from gzip archive and launches data_scan"""
        candidates = []
        try:
            with gzip.open(io.BytesIO(data_provider.data)) as f:
                new_path = data_provider.file_path if ".gz" != Util.get_extension(
                    data_provider.file_path) else data_provider.file_path[:-3]
                gzip_content_provider = DataContentProvider(data=f.read(),
                                                            file_path=data_provider.file_path,
                                                            file_type=Util.get_extension(new_path),
                                                            info=f"{data_provider.info}|GZIP|{new_path}")
                new_limit = recursive_limit_size - len(gzip_content_provider.data)
                gzip_candidates = self.recursive_scan(gzip_content_provider, depth, new_limit)
                candidates.extend(gzip_candidates)
        except Exception as gzip_exc:
            logger.error(f"{data_provider.file_path}:{gzip_exc}")
        return candidates
