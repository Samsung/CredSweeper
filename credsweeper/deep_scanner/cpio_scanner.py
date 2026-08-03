import logging
import struct
from abc import ABC
from typing import List, Optional, Generator, Tuple

from credsweeper.common.constants import UTF_8, MIN_DATA_LEN
from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class CpioScanner(AbstractScanner, ABC):
    """Implements cpio scanning"""

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """According https://en.wikipedia.org/wiki/List_of_file_signatures"""
        if data.startswith((b"\x71\xc7", b"\xc7\x71", b"070707", b"070701", b"070702")) and data.endswith(b"\0\0"):
            return True
        return False

    ASCII_HEADER = struct.Struct("6s8s8s8s8s8s8s8s8s8s8s8s8s8s")

    @staticmethod
    def _read_ascii(data: bytes, offset: int, limit: int) -> Tuple[int, str, Optional[bytes], int]:
        (__magic, __ino, __mode, __uid, __gid, __nlink, __mtime, _filesize, __devmajor, __devminor, __rdevmajor,
         __rdevminor, _namesize, __check) = CpioScanner.ASCII_HEADER.unpack_from(data, offset)

        namesize = int(_namesize, 16)
        filesize = int(_filesize, 16)

        name_start = offset + CpioScanner.ASCII_HEADER.size
        name_end = name_start + namesize
        if namesize < limit and name_end < len(data):
            name = data[name_start:name_end - 1].decode(UTF_8, "surrogateescape")
        else:
            name = ''

        data_start = name_end + (0x3 & (4 - (0x3 & name_end)))
        data_end = data_start + filesize
        if filesize < limit and data_end <= len(data):
            content = data[data_start:data_end]
        else:
            content = None

        next_offset = data_end + (0x3 & (4 - (0x3 & data_end)))
        return data_start, name, content, next_offset

    ODC_HEADER = struct.Struct("=6s6s6s6s6s6s6s6s11s6s11s")

    @staticmethod
    def _read_odc(data: bytes, offset: int, limit: int) -> Tuple[int, str, Optional[bytes], int]:
        (__magic, __dev, __ino, __mode, __uid, __gid, __nlink, __rdev, __mtime, _namesize,
         _filesize) = CpioScanner.ODC_HEADER.unpack_from(data, offset)

        namesize = int(_namesize, 8)
        filesize = int(_filesize, 8)

        name_start = offset + CpioScanner.ODC_HEADER.size
        name_end = name_start + namesize
        if namesize < limit and name_end < len(data):
            name = data[name_start:name_end - 1].decode(UTF_8, "surrogateescape")
        else:
            name = ''

        data_start = name_end
        data_end = data_start + filesize
        if filesize < limit and data_end <= len(data):
            content = data[data_start:data_end]
        else:
            content = None

        return data_start, name, content, data_end

    @staticmethod
    def _read_binary(data: bytes, offset: int, limit: int,
                     header: struct.Struct) -> Tuple[int, str, Optional[bytes], int]:
        (__magic, __dev, __ino, __mode, __uid, __gid, __nlink, __rdev, __mtimehigh, __mtimelow, namesize, filesizehigh,
         filesizelow) = header.unpack_from(data, offset)

        filesize = (filesizehigh << 16) | filesizelow

        name_start = offset + header.size
        name_end = name_start + namesize
        if namesize < limit and name_end < len(data):
            name = data[name_start:name_end - 1].decode(UTF_8, "surrogateescape")
        else:
            name = ''

        data_start = name_end + (namesize % 2)
        data_end = data_start + filesize
        if filesize < limit and data_end <= len(data):
            content = data[data_start:data_end]
        else:
            content = None

        next_offset = data_end + (filesize % 2)
        return data_start, name, content, next_offset

    BIN_LE_HEADER = struct.Struct("<2sHHHHHHHHHHHH")

    @staticmethod
    def _read_binary_le(data: bytes, offset: int, limit: int) -> Tuple[int, str, Optional[bytes], int]:
        return CpioScanner._read_binary(data, offset, limit, CpioScanner.BIN_LE_HEADER)

    BIN_BE_HEADER = struct.Struct(">2sHHHHHHHHHHHH")

    @staticmethod
    def _read_binary_be(data: bytes, offset: int, limit: int) -> Tuple[int, str, Optional[bytes], int]:
        return CpioScanner._read_binary(data, offset, limit, CpioScanner.BIN_BE_HEADER)

    @staticmethod
    def walk_cpio(data: bytes, limit: int) -> Generator[Tuple[int, str, bytes], None, None]:
        """Processes sequence of cpio archive and yields offset, name and data"""

        offset = 0
        while offset < len(data):
            if data.startswith((b"070701", b"070702"), offset):
                data_start, name, content, offset = CpioScanner._read_ascii(data, offset, limit)
            elif data.startswith(b"070707", offset):
                data_start, name, content, offset = CpioScanner._read_odc(data, offset, limit)
            elif data.startswith(b"\x71\xc7", offset):
                data_start, name, content, offset = CpioScanner._read_binary_be(data, offset, limit)
            elif data.startswith(b"\xc7\x71", offset):
                data_start, name, content, offset = CpioScanner._read_binary_le(data, offset, limit)
            else:
                raise ValueError(
                    f"Unsupported CPIO record at 0x{offset:8x} "
                    f": {repr(bytes(x for x in data[offset:offset + min(MIN_DATA_LEN, len(data) - offset)]))}")
            if "TRAILER!!!" == name:
                break
            if content is not None and MIN_DATA_LEN < len(content):
                yield data_start, name, content

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Extracts data file from .ar (cpioian) archive and launches data_scan"""
        try:
            candidates: List[Candidate] = []
            for data_start, name, data in CpioScanner.walk_cpio(data_provider.data, recursive_limit_size):
                cpio_content_provider = DataContentProvider(data=data,
                                                            file_path=data_provider.file_path,
                                                            file_type=Util.get_type(name),
                                                            info=f"{data_provider.info}|CPIO:0x{data_start:x}:{name}")
                cpio_candidates = self.recursive_scan(cpio_content_provider, depth, recursive_limit_size)
                candidates.extend(cpio_candidates)
            return candidates
        except Exception as exc:
            logger.warning(exc)
        return None
