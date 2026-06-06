import logging
import struct
import zlib
from abc import ABC
from typing import List, Optional, Generator, Tuple

from credsweeper.common.constants import MIN_DATA_LEN
from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class DexScanner(AbstractScanner, ABC):
    """Implements DEX scanning"""

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """Checks header magic for various DEX formats and versions"""
        if data.startswith((b"dex\n03", b"dey\n03")) and 7 < len(data) and 0x35 <= data[6] <= 0x39 and 0 == data[7]:
            return True
        return False

    @staticmethod
    def walk_dex(data: bytes) -> Generator[Tuple[int, bytes], None, None]:
        data_len = len(data)
        if 0x70 > data_len:
            raise ValueError(f"Small header size {data_len}")
        header_size = struct.unpack("<L", data[0x24:0x28])[0]
        if 0x70 != header_size:
            raise ValueError(f"Unsupported header size {header_size}")
        if b"\x78\x56\x34\x12" != data[0x28:0x2C]:
            raise ValueError(f"Unsupported endian tag {data[0x28:0x2C]}")
        checksum = struct.unpack("<L", data[0x8:0xC])[0]
        adler32 = zlib.adler32(data[0xC:], 1)
        if checksum != adler32:
            logger.warning("Checksum mismatch")

        string_ids_size = struct.unpack("<L", data[0x38:0x3C])[0]
        string_ids_off = struct.unpack("<L", data[0x3C:0x40])[0]
        for n in range(string_ids_size):
            ptr_offset = string_ids_off + (n << 2)
            obj_offset = struct.unpack("<L", data[ptr_offset:ptr_offset + 4])[0]
            str_offset, str_size = Util.read_varuint(data, obj_offset, 19)
            text = data[obj_offset+ str_offset: obj_offset+str_offset + str_size]
            if MIN_DATA_LEN < str_size:
                logger.debug("%s",text)
                yield obj_offset + str_offset, text

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Extracts data from binary"""
        try:
            candidates = []
            for offset, data in DexScanner.walk_dex(data_provider.data):
                dex_content_provider = DataContentProvider(data=data,
                                                           file_path=data_provider.file_path,
                                                           file_type=data_provider.file_type,
                                                           info=f"{data_provider.info}|DEX:0x{offset:x}")
                dex_candidates = self.recursive_scan(dex_content_provider, depth, recursive_limit_size)
                candidates.extend(dex_candidates)
            return candidates
        except Exception as dex_exc:
            logger.warning("%s:%s", data_provider.file_path, dex_exc)
        return None
