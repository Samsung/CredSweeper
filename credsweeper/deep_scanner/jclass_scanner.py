import io
import logging
import struct
from abc import ABC
from typing import List, Optional

from credsweeper.common.constants import MIN_DATA_LEN, UTF_8
from credsweeper.credentials import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.struct_content_provider import StructContentProvider

logger = logging.getLogger(__name__)


class JclassScanner(AbstractScanner, ABC):
    """Implements java .class scanning"""

    @staticmethod
    def u2(stream: io.BytesIO):
        """Extracts unsigned 16 bit big-endian"""
        return struct.unpack(">H", stream.read(2))[0]

    @staticmethod
    def get_utf8_constants(stream: io.BytesIO) -> List[str]:
        """Extracts only Utf8 constants from java ClassFile"""
        result = []
        item_count = JclassScanner.u2(stream)
        while 0 < item_count:
            # actual number of items is one less!
            item_count -= 1
            tag = struct.unpack("B", stream.read(1))[0]
            if 1 == tag:
                length = JclassScanner.u2(stream)
                data = stream.read(int(length))
                if MIN_DATA_LEN <= length:
                    value = data.decode(encoding=UTF_8, errors="replace")
                    result.append(value)
            elif tag in (3, 4, 9, 10, 11, 12, 18):
                _ = stream.read(4)
            elif tag in (7, 8, 16):
                _ = stream.read(2)
            elif tag in (5, 6):
                _ = stream.read(8)
            elif 15 == tag:
                _ = stream.read(3)
            else:
                logger.error(f"Unknown tag {tag}")
                break
        return result

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Extracts data from binary"""
        candidates = None
        try:
            stream = io.BytesIO(data_provider.data)
            stream.read(4)  # magic
            minor = JclassScanner.u2(stream)
            major = JclassScanner.u2(stream)
            constants = JclassScanner.get_utf8_constants(stream)
            struct_content_provider = StructContentProvider(struct=constants,
                                                            file_path=data_provider.file_path,
                                                            file_type=data_provider.file_type,
                                                            info=f"{data_provider.info}|Java.{major}.{minor}")
            new_limit = recursive_limit_size - sum(len(x) for x in constants)
            gzip_candidates = self.structure_scan(struct_content_provider, depth, new_limit)
            return gzip_candidates
        except Exception as jclass_exc:
            logger.error(f"{data_provider.file_path}:{jclass_exc}")
        return candidates
