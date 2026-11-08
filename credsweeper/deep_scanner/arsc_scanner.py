import logging
import struct
from abc import ABC
from enum import IntEnum
from typing import Iterator, List, Optional, Tuple

from credsweeper.common.constants import MIN_DATA_LEN, UTF_16_LE
from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class ArscScanner(AbstractScanner, ABC):
    """Implements Android Resources (.arsc) scanning"""

    class ResType(IntEnum):
        """Chunk type ids of Android binary resource table (.arsc), RES_*_TYPE in AOSP ResourceTypes.h"""
        NULL = 0x0000
        STRING_POOL = 0x0001
        TABLE = 0x0002
        XML = 0x0003
        TABLE_PACKAGE = 0x0200
        TABLE_TYPE = 0x0201
        TABLE_TYPE_SPEC = 0x0202
        TABLE_LIBRARY = 0x0203
        TABLE_OVERLAYABLE = 0x0204
        TABLE_OVERLAYABLE_POLICY = 0x0205
        TABLE_STAGED_ALIAS = 0x0206

    # ResChunk_header: type (u16), headerSize (u16), size (u32)
    CHUNK_HEADER = struct.Struct("<HHI")

    # Chunks which contain nested chunks
    CONTAINERS = {
        ResType.TABLE,
        ResType.TABLE_PACKAGE,
        ResType.TABLE_OVERLAYABLE,
    }

    # Binary chunks without text: entries hold only indexes into the global string pool
    BINARY_ONLY = {
        ResType.TABLE_TYPE,
        ResType.TABLE_TYPE_SPEC,
    }

    UTF8_FLAG = 0x100

    @staticmethod
    def utf16z(raw: bytes) -> str:
        """Decodes UTF-16LE fixed-size field and cuts it at the first NUL."""
        txt = raw.decode(UTF_16_LE, errors="strict")
        return txt.split('\0', maxsplit=1)[0]

    @staticmethod
    def parse_string_pool(buf: bytes, pos: int) -> List[str]:
        """Parses STRING_POOL chunk located at offset `pos`, returns list of strings."""
        _, hdr_size, _size = ArscScanner.CHUNK_HEADER.unpack_from(buf, pos)
        count, _styles, flags, strings_start, _ = struct.unpack_from("<IIIII", buf, pos + 8)
        is_utf8 = bool(flags & ArscScanner.UTF8_FLAG)
        offsets = struct.unpack_from(f"<{count}I", buf, pos + hdr_size)
        base = pos + strings_start
        out = []

        for off in offsets:
            p = base + off
            if is_utf8:
                # Two lengths: chars count, then bytes count (1 or 2 bytes each); skip the first
                p += 2 if buf[p] & 0x80 else 1
                b = buf[p]
                if b & 0x80:
                    nbytes = ((b & 0x7F) << 8) | buf[p + 1]
                    p += 2
                else:
                    nbytes = b
                    p += 1
                out.append(buf[p:p + nbytes].decode("utf-8", errors="replace"))
            else:
                # Length in UTF-16 code units (1 or 2 u16 words)
                n = struct.unpack_from("<H", buf, p)[0]
                p += 2
                if n & 0x8000:
                    n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", buf, p)[0]
                    p += 2
                out.append(buf[p:p + n * 2].decode(UTF_16_LE, errors="replace"))
        return out

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """Checks RES_TABLE_TYPE header and size. According https://apktool.org/wiki/advanced/resources-arsc/"""
        if data.startswith(b"\x02\x00\x0C\x00") and 12 < len(data):
            size = struct.unpack_from("<I", data, offset=4)[0]
            return bool(size <= len(data))
        return False

    @staticmethod
    def walk_arsc(data: bytes) -> Iterator[Tuple[int, int, str, bytes]]:
        """Walks over .arsc chunks and yields (offset, type, name, payload).

        Containers are expanded and not yielded.
        STRING_POOL is yielded string by string (name is "<pool>[<index>]", offset is the pool offset).
        Binary-only chunks (TABLE_TYPE, TABLE_TYPE_SPEC) are skipped.
        """

        def walk(start: int, end: int, pkg: Optional[dict] = None) -> Iterator[Tuple[int, int, str, bytes]]:
            pos = start
            while pos < end:
                if pos + ArscScanner.CHUNK_HEADER.size > end:
                    raise ValueError(f"Truncated chunk header at 0x{pos:x}")

                ctype, hdr_size, size = ArscScanner.CHUNK_HEADER.unpack_from(data, pos)

                if hdr_size < ArscScanner.CHUNK_HEADER.size or size < hdr_size:
                    raise ValueError(f"Invalid chunk at 0x{pos:x}: headerSize={hdr_size}, size={size}")
                if pos + size > end:
                    raise ValueError(f"Chunk at 0x{pos:x} (size={size}) exceeds parent boundary")

                try:
                    rtype = ArscScanner.ResType(ctype)
                    name = rtype.name
                except ValueError:
                    rtype = None
                    name = f"UNKNOWN_0x{ctype:04x}"

                child_pkg = pkg

                if rtype is ArscScanner.ResType.TABLE_PACKAGE:
                    # name: 128 x UTF-16 at +12; typeStrings at +268; keyStrings at +276
                    name = ArscScanner.utf16z(data[pos + 12:pos + 12 + 256])
                    type_strings, = struct.unpack_from("<I", data, pos + 268)
                    key_strings, = struct.unpack_from("<I", data, pos + 276)
                    child_pkg = {
                        "type_off": pos + type_strings,
                        "key_off": pos + key_strings,
                        "types": ArscScanner.parse_string_pool(data, pos + type_strings) if type_strings else [],
                    }

                elif rtype is ArscScanner.ResType.STRING_POOL:
                    if pkg is None:
                        name = "global"
                    elif pos == pkg["type_off"]:
                        name = "types"
                    elif pos == pkg["key_off"]:
                        name = "keys"
                    for idx, string in enumerate(ArscScanner.parse_string_pool(data, pos)):
                        if MIN_DATA_LEN <= len(string):
                            yield pos, ctype, f"{name}[{idx}]", string.encode()
                    pos += size
                    continue

                elif rtype in ArscScanner.BINARY_ONLY:
                    pos += size
                    continue

                elif rtype is ArscScanner.ResType.TABLE_OVERLAYABLE:
                    # name: 256 x UTF-16 at +8
                    name = ArscScanner.utf16z(data[pos + 8:pos + 8 + 512])

                if rtype in ArscScanner.CONTAINERS:
                    yield from walk(pos + hdr_size, pos + size, child_pkg)
                else:
                    yield pos, ctype, name, data[pos:pos + size]

                pos += size

        yield from walk(0, len(data))

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Extracts strings from .arsc and launches recursive scan for each"""
        try:
            candidates: List[Candidate] = []
            for offset, ctype, name, data in ArscScanner.walk_arsc(data_provider.data):
                arsc_content_provider = DataContentProvider(
                    data=data,
                    file_path=data_provider.file_path,
                    file_type=Util.get_type(name),
                    info=f"{data_provider.info}|ARSC:0x{offset:x}:{ctype}:{name}")
                candidates.extend(self.recursive_scan(arsc_content_provider, depth, recursive_limit_size))
            return candidates
        except Exception as exc:  # pylint: disable=broad-exception-caught
            # fallback
            logger.warning("%s:%s:%s", type(exc), exc, data_provider.descriptor)
        return None
