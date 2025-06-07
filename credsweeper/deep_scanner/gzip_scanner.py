import gzip
import io
import logging
from abc import ABC
from pathlib import Path
from typing import List, Optional

from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class GzipScanner(AbstractScanner, ABC):
    """Realises gzip scanning"""

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Extracts data from gzip archive and launches data_scan"""
        try:
            with gzip.open(io.BytesIO(data_provider.data)) as f:
                file_path = Path(data_provider.file_path)
                new_path = file_path.as_posix()
                if ".gz" == file_path.suffix:
                    new_path = new_path[:-3]
                gzip_content_provider = DataContentProvider(data=f.read(),
                                                            file_path=new_path,
                                                            file_type=Util.get_extension(new_path),
                                                            info=f"{data_provider.info}|GZIP:{new_path}")
                new_limit = recursive_limit_size - len(gzip_content_provider.data)
                gzip_candidates = self.recursive_scan(gzip_content_provider, depth, new_limit)
                return gzip_candidates
        except Exception as gzip_exc:
            logger.error(f"{data_provider.file_path}:{gzip_exc}")
        return None
