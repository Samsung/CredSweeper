import logging
import struct
import zlib
from abc import ABC
from typing import List, Optional, Generator, Tuple

from credsweeper.common.constants import MIN_DATA_LEN
from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.logger import TRACE
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class ModifiedUtf8Error(ValueError):
    """Auxiliary class error for DexScanner"""


class DexScanner(AbstractScanner, ABC):
    """Implements DEX scanning"""

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """Checks header magic for various DEX formats and versions"""
        if data.startswith((b"dex\n03", b"dey\n03")) and 7 < len(data) and 0x35 <= data[6] <= 0x39 and 0 == data[7]:
            return True
        return False

    @staticmethod
    def decode_mutf8(data: bytes) -> bytes:
        """Decode DEX Modified UTF-8 bytes to a Python str."""
        utf16 = bytearray()
        i = 0
        size = len(data)
        while i < size:
            b0 = data[i]
            i += 1
            if b0 < 0x80:
                # 1 byte ASCII
                cp = b0
            elif 0xC0 == b0 & 0xE0:
                # 2 bytes
                if i >= size:
                    raise ModifiedUtf8Error("Incomplete MUTF-8 sequence")
                b1 = data[i]
                i += 1
                if 0x80 != b1 & 0xC0:
                    raise ModifiedUtf8Error("Invalid MUTF-8 continuation byte")
                cp = ((b0 & 0x1F) << 6) | (b1 & 0x3F)
            elif 0xE0 == b0 & 0xF0:
                # 3 bytes surrogates
                if i + 1 >= size:
                    raise ModifiedUtf8Error("Incomplete MUTF-8 sequence")
                b1, b2 = data[i], data[i + 1]
                i += 2
                if 0x80 != b1 & 0xC0 or 0x80 != b2 & 0xC0:
                    raise ModifiedUtf8Error("Invalid MUTF-8 continuation byte")
                cp = ((b0 & 0x0F) << 12) | ((b1 & 0x3F) << 6) | (b2 & 0x3F)
            else:
                raise ModifiedUtf8Error(f"Invalid MUTF-8 lead byte 0x{b0:02x}")
            utf16.extend(cp.to_bytes(2, "big"))
        return bytes(utf16)

    @staticmethod
    def walk_dex(data: bytes) -> Generator[Tuple[int, bytes], None, None]:
        """Processes sequence of DEX file and yields offset and bytes from strings"""
        data_len = len(data)
        if 0x70 > data_len:
            raise ValueError(f"Small header size {data_len}")
        header_size = struct.unpack("<L", data[0x24:0x28])[0]
        if 0x70 != header_size:
            raise ValueError(f"Unsupported header size {header_size}")
        if b"\x78\x56\x34\x12" != data[0x28:0x2C]:
            raise ValueError(f"Unsupported endian tag {repr(data[0x28:0x2C])}")
        checksum = struct.unpack("<L", data[0x8:0xC])[0]
        adler32 = zlib.adler32(data[0xC:], 1)
        if checksum != adler32:
            logger.warning("Checksum mismatch")

        string_ids_size = struct.unpack("<L", data[0x38:0x3C])[0]
        string_ids_off = struct.unpack("<L", data[0x3C:0x40])[0]
        for n in range(string_ids_size):
            ptr_offset = string_ids_off + (n << 2)
            obj_offset = struct.unpack("<L", data[ptr_offset:ptr_offset + 4])[0]
            varint_len, utf16_size = Util.read_varuint(data, obj_offset, 19)
            if utf16_size < MIN_DATA_LEN:
                continue
            start = obj_offset + varint_len
            end = data.find(b'\x00', start)
            if end < 0:
                raise ValueError(f"Unterminated string at {start:x}")
            chunk = data[start:end]
            try:
                yield start, DexScanner.decode_mutf8(chunk)
            except ModifiedUtf8Error as exc:
                logger.log(TRACE, "%s %s:%s", exc, f"{start:x}", f"{end:x}")
                yield start, chunk

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
                candidates.extend(self.recursive_scan(dex_content_provider, depth, recursive_limit_size))
            return candidates
        except Exception as exc:  # pylint: disable=broad-exception-caught
            # fallback
            logger.warning("%s:%s:%s", type(exc), exc, data_provider.descriptor)
        return None
