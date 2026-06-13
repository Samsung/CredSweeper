import io
import logging
import plistlib
from abc import ABC
from typing import List, Optional

from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.struct_content_provider import StructContentProvider

logger = logging.getLogger(__name__)


class PlistScanner(AbstractScanner, ABC):
    """Implements binary plist data scanning"""

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """According https://en.wikipedia.org/wiki/List_of_file_signatures - Binary Property List file"""
        if data.startswith(b"bplist00"):
            return True
        return False

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Extracts data file from property list data and scan like a structure"""
        try:
            structure = plistlib.load(io.BytesIO(data_provider.data))
            struct_content_provider = StructContentProvider(struct=structure,
                                                            file_path=data_provider.file_path,
                                                            file_type=data_provider.file_type,
                                                            info=f"{data_provider.info}|BPLIST")
            candidates = self.structure_scan(struct_content_provider, depth, recursive_limit_size)
            return candidates
        except Exception as exc:
            logger.warning(exc)
        return None
