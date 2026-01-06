import logging
import lzma
from abc import ABC
from pathlib import Path
from typing import List, Optional, Union

from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class LzmaScanner(AbstractScanner, ABC):
    """Implements lzma scanning"""

    @staticmethod
    def match(data: Union[bytes, bytearray]) -> bool:
        """According https://en.wikipedia.org/wiki/List_of_file_signatures - lzma also xz"""
        if data.startswith((b"\xFD7zXZ\x00", b"\x5D\x00\x00")):
            return True
        return False

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Extracts data from lzma archive and launches data_scan"""
        try:
            file_path = Path(data_provider.file_path)
            new_path = file_path.as_posix()
            if ".xz" == file_path.suffix:
                new_path = new_path[:-3]
            elif ".lzma" == file_path.suffix:
                new_path = new_path[:-5]
            lzma_content_provider = DataContentProvider(data=lzma.decompress(data_provider.data),
                                                        file_path=new_path,
                                                        file_type=Util.get_extension(new_path),
                                                        info=f"{data_provider.info}|LZMA:{file_path}")
            new_limit = recursive_limit_size - len(lzma_content_provider.data)
            lzma_candidates = self.recursive_scan(lzma_content_provider, depth, new_limit)
            return lzma_candidates
        except Exception as lzma_exc:
            logger.error(f"{data_provider.file_path}:{lzma_exc}")
        return None
