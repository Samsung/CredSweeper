import logging
import pickletools
from abc import ABC
from typing import List, Optional

from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.struct_content_provider import StructContentProvider

logger = logging.getLogger(__name__)


class PickleScanner(AbstractScanner, ABC):
    """Implements pickle data scanning with pickletools"""

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """Supports protocols 3, 4 and 5"""
        if data.startswith(b'\x80') and 32 < len(data) and 0x03 <= data[1] <= 0x05:
            return True
        return False

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Extracts arguments only for safe disassembled pickle"""
        try:
            candidates: List[Candidate] = []
            for opcode_info, arg, pos in pickletools.genops(data_provider.data):
                if arg is None or isinstance(arg, (int, float)):
                    # skip unsupported simple data
                    continue
                struct_content_provider = StructContentProvider(struct={pos: arg},
                                                                file_path=data_provider.file_path,
                                                                file_type=data_provider.file_type,
                                                                info=f"{data_provider.info}|PICKLE:{opcode_info.name}")
                if new_candidates := self.structure_scan(struct_content_provider, depth, recursive_limit_size):
                    candidates.extend(new_candidates)
            return candidates
        except Exception as exc:
            logger.warning(exc)
        return None
