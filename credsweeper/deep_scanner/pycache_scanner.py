import logging
import struct
from abc import ABC
from typing import List, Optional, Generator, Tuple

from credsweeper.common.constants import MIN_DATA_LEN
from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider

logger = logging.getLogger(__name__)

SLOT_SIZE = 36


class PycacheScanner(AbstractScanner, ABC):
    """Implements python cache files scanning"""

    MATCHES_SIGNATURES = (
        b"\r\n\x00\x00\x00\x00",
        b"\r\n\x01\x00\x00\x00",
        b"\r\n\x03\x00\x00\x00",
    )

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """Checks header magic for 3 actual variants"""
        if 32 < len(data) and data[2:8] in PycacheScanner.MATCHES_SIGNATURES:
            return True
        return False

    @staticmethod
    def walk_pycache(data: bytes, limit: int) -> Generator[Tuple[int, bytes], None, None]:
        """Yields (offset, bytes) from python cache file"""
        # skip header
        offset = 16
        # start parsing as obj
        stack = [-2]
        stack_size = SLOT_SIZE

        while stack and stack_size < limit:
            arg = stack.pop()
            stack_size -= SLOT_SIZE

            if 0 <= arg:
                # skip raw bytes
                offset += arg
                continue

            type_code = chr(0x7F & data[offset])

            if -1 == arg:
                # processing dict
                if '0' == type_code:
                    offset += 1
                    continue
                stack.extend([-1, -2, -2])
                stack_size += 3 * SLOT_SIZE

            elif -2 == arg:
                # Object
                offset += 1

                if type_code in ('0', 'N', 'F', 'T', 'S', '.'):
                    # skip
                    pass

                elif type_code in ('i', 'r'):
                    # int32
                    offset += 4

                elif 'g' == type_code:
                    # binary float
                    offset += 8

                elif 'y' == type_code:
                    # binary complex
                    offset += 16

                elif 'f' == type_code:
                    # legacy text float: 1-байт len + ascii
                    n = data[offset]
                    offset += 1 + n

                elif 'x' == type_code:
                    # legacy complex: 2x
                    n = data[offset]
                    offset += 1 + n
                    n = data[offset]
                    offset += 1 + n

                elif 'l' == type_code:
                    # long
                    n = struct.unpack_from('<i', data, offset)[0]
                    offset += 4 + abs(n) << 1

                elif type_code in ('(', '[', '<', '>'):
                    # tuple/list/set/frozenset, 4-байт count
                    count = struct.unpack_from('<I', data, offset)[0]
                    stack_size += SLOT_SIZE * count
                    if limit < stack_size:
                        raise ValueError(f"Overhead size {count!r} at {offset:#08x}")
                    stack.extend([-2] * count)
                    offset += 4

                elif ')' == type_code:
                    # small tuple, 1-byte count
                    count = data[offset]
                    stack_size += SLOT_SIZE * count
                    if limit < stack_size:
                        raise ValueError(f"Overhead size {count!r} at {offset:#08x}")
                    stack.extend([-2] * count)
                    offset += 1

                elif '{' == type_code:
                    # dict
                    stack.append(-1)
                    stack_size += SLOT_SIZE

                elif 'c' == type_code:
                    # code object (layout 3.11) skip 20 (5 raw int32) -> 8 obj -> skip 4 (int32) -> 2 obj.
                    stack.extend([-2, -2, 4, -2, -2, -2, -2, -2, -2, -2, -2, 20])
                    stack_size += 12 * SLOT_SIZE

                elif type_code in ('z', 'Z'):
                    # short ascii (interned)
                    size = data[offset]
                    offset += 1
                    if MIN_DATA_LEN < size <= limit:
                        yield offset, data[offset:offset + size]
                    elif limit < size:
                        logger.info("Skip overhead at %s limit: %s size: %s", f"{offset:#08x}", limit, size)
                    else:
                        logger.debug("Skip small data at %s limit: %s size: %s", f"{offset:#08x}", limit, size)
                    offset += size

                elif type_code in ('s', 'u', 'a', 'A', 't'):
                    # raw bytes / unicode / ascii / interned
                    size = struct.unpack_from('<I', data, offset)[0]
                    offset += 4
                    if MIN_DATA_LEN < size <= limit:
                        yield offset, data[offset:offset + size]
                    elif limit < size:
                        logger.info("Skip overhead at %s limit: %s size: %s", f"{offset:#08x}", limit, size)
                    else:
                        logger.debug("Skip small data at %s limit: %s size: %s", f"{offset:#08x}", limit, size)
                    offset += size
                else:
                    raise ValueError(f"Unknown marshal type {type_code!r} at {offset:#08x}")

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Extracts data from binary"""
        try:
            candidates = []
            for offset, data in PycacheScanner.walk_pycache(data_provider.data, recursive_limit_size):
                str_struct_provider = DataContentProvider(data=data,
                                                          file_path=data_provider.file_path,
                                                          file_type=data_provider.file_type,
                                                          info=f"{data_provider.info}|PYCACHE:{offset}")
                pyc_candidates = self.recursive_scan(str_struct_provider, depth, recursive_limit_size)
                candidates.extend(pyc_candidates)
            return candidates
        except Exception as pyc_exc:
            logger.warning("%s:%s", data_provider.file_path, pyc_exc)
        return None
