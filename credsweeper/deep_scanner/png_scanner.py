import logging
import struct
from abc import ABC
from typing import List, Optional, Generator, Tuple

from credsweeper.common.constants import LATIN_1, UTF_8
from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider

logger = logging.getLogger(__name__)


class PngScanner(AbstractScanner, ABC):
    """Implements PNG scanning for text chunks"""

    @staticmethod
    def match(data: bytes) -> bool:
        """Returns True if prefix match"""
        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            return True
        return False

    @staticmethod
    def yield_png_chunks(data: bytes) -> Generator[Tuple[int, str, bytes], None, None]:
        """Processes PNG chunks and yields offset, type and data"""
        offset = 8  # b"\x89PNG\r\n\x1a\n"
        data_limit = len(data) - 12
        while offset <= data_limit:
            chunk_size = struct.unpack(">I", data[offset:offset + 4])[0]
            chunk_type = data[offset + 4:offset + 8]
            offset += 8
            if len(data) < offset + chunk_size:
                raise ValueError(f"PNG chunk size {chunk_size} exceeds data limit 0x{offset:x}")
            match chunk_type:
                case b"IEND":
                    # https://www.w3.org/TR/png/#11IEND
                    break
                case b"tEXt":
                    # https://www.w3.org/TR/png/#11tEXt
                    keyword, text_data = data[offset:offset + chunk_size].split(b'\0', 1)
                    yield offset, f"PNG_TEXT:{keyword.decode(encoding=LATIN_1, errors='strict')}", text_data
                case b"zTXt":
                    # https://www.w3.org/TR/png/#11zTXt
                    keyword, ztxt_data = data[offset:offset + chunk_size].split(b'\0', 1)
                    if not ztxt_data.startswith(b'\0'):
                        raise ValueError(f"Unsupported compression method {ztxt_data[0]}")
                    yield offset, f"PNG_ZTXT:{keyword.decode(encoding=LATIN_1, errors='strict')}", ztxt_data[1:]
                case b"iTXt":
                    # https://www.w3.org/TR/png/#11iTXt
                    keyword, itxt_data = data[offset:offset + chunk_size].split(b'\0', 1)

                    if itxt_data.startswith(b"\x00\x00"):
                        compression = False
                    elif itxt_data.startswith(b"\x01\x00"):
                        compression = True
                    else:
                        raise ValueError(f"Unsupported compression {repr(itxt_data[:2])}")
                    lang_tag, itxt_data = itxt_data[2:].split(b'\0', 1)
                    trans_key, itxt_data = itxt_data.split(b'\0', 1)
                    yield (offset, f"PNG_ITXT_{'1' if compression else '0'}"
                           f":{keyword.decode(encoding=UTF_8)}"
                           f":{lang_tag.decode(encoding=UTF_8)}"
                           f":{trans_key.decode(encoding=UTF_8)}", itxt_data)
                case _:
                    pass
            # skip crc verification
            offset += chunk_size + 4

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Tries to scan each row as structure with column name in key"""
        try:
            candidates: List[Candidate] = []
            for offset, chunk_type, data in PngScanner.yield_png_chunks(data_provider.data):
                png_content_provider = DataContentProvider(data=data,
                                                           file_path=data_provider.file_path,
                                                           file_type=data_provider.file_type,
                                                           info=f"{data_provider.info}|{chunk_type}:0x{offset:x}")
                new_limit = recursive_limit_size - len(data)
                png_candidates = self.recursive_scan(png_content_provider, depth, new_limit)
                candidates.extend(png_candidates)
            return candidates
        except Exception as exc:
            logger.error(exc)
        return None
