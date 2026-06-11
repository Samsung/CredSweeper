import logging
from abc import ABC
from typing import List, Optional, Generator, Tuple

from credsweeper.common.constants import MIN_DATA_LEN
from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class ProtobufScanner(AbstractScanner, ABC):
    """Implements protobuf (ar) scanning"""

    @staticmethod
    def read_wire(data: bytes | bytearray, offset: int) -> Tuple[int, int]:
        """Reads wire to detect sizes

        Returns: size of wire type (with primitives types), size of data (length-delimited)
        """
        n, s = Util.read_varuint(data, offset, 10)
        if 0 < n:
            t = 0x3 & s
            if 0 == t:
                # varint
                _n, _ = Util.read_varuint(data, offset + n, 10)
                if 0 < _n:
                    return n + _n, 0
            elif 1 == t:
                # 64 bit fixed
                return n + 8, 0
            elif 2 == t:
                # length-delimited
                _n, _s = Util.read_varuint(data, offset + n, 10)
                if 0 < _n:
                    return n + _n, _s
            elif 3 == t or 4 == t:
                # deprecated
                return n, 0
            elif 5 == t:
                # 32 bit fixed
                return n + 4, 0
        return -1, 0

    @staticmethod
    def match_protobuf(data: bytes | bytearray, offset: int, limit: int) -> bool:
        """Process data from start to end as simple protobuf chunk

        Returns: True when whole chunk was utilized with protobuf structure
        """
        while offset < limit:
            n, s = ProtobufScanner.read_wire(data, offset)
            if 0 < n:
                offset += n + s
            else:
                break
        else:
            return bool(offset == limit)
        return False

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """Simple structure check for whole data"""
        if data:
            return ProtobufScanner.match_protobuf(data, 0, len(data))
        return False

    @staticmethod
    def walk_protobuf(data: bytes, offset: int, limit: int) -> Generator[Tuple[int, bytes], None, None]:
        """Processes sequence of protobuf and yields offset and data recursive"""
        while offset < limit:
            n, s = ProtobufScanner.read_wire(data, offset)
            if 0 > n:
                raise ValueError(f"Wrong data at 0x{offset:x}")
            offset += n
            if MIN_DATA_LEN < s:
                # yield valuable bytes only
                if ProtobufScanner.match_protobuf(data, offset, offset + s):
                    yield from ProtobufScanner.walk_protobuf(data, offset, offset + s)
                else:
                    yield offset, data[offset:offset + s]
            offset += s

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Extracts data file from protobuf payload and launches data_scan"""
        try:
            candidates: List[Candidate] = []
            for offset, data in ProtobufScanner.walk_protobuf(data_provider.data, 0, len(data_provider.data)):
                provider = DataContentProvider(data=data,
                                               file_path=data_provider.file_path,
                                               file_type=data_provider.file_type,
                                               info=f"{data_provider.info}|PROTO:0x{offset:x}")
                protobuf_candidates = self.recursive_scan(provider, depth, recursive_limit_size)
                candidates.extend(protobuf_candidates)
            return candidates
        except Exception as exc:
            logger.warning(exc)
        return None
