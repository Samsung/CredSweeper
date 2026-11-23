import logging
import sys
from abc import ABC
from typing import List, Optional, Mapping

if (3, 14) <= sys.version_info:
    from compression import zstd  # pylint: disable=E0401
else:
    # todo: remove when Python 3.11, 3.12, 3.13 support ends:
    import zstandard as zstd  # pylint: disable=E0401

from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider

logger = logging.getLogger(__name__)


class ZstdScannerException(zstd.ZstdError):
    """The decompressed size is over the limit, or the limit cannot be applied.

    It is a subclass of zstd.ZstdError, so `except zstd.ZstdError` catches any zstd failure,
    while data_scan() handles this one separately: it is an expected case, not a broken archive.
    """


class ZstdScanner(AbstractScanner, ABC):
    """Implements zstd data decompression and scan"""

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """Returns True if data looks like compressed data with zstd"""
        # heuristic: magic + header + one block is less than 17 bytes, such a frame holds almost nothing to scan
        if data.startswith(b"\x28\xB5\x2F\xFD") and 16 < len(data):
            return True
        return False

    @staticmethod
    def decompress(limit: int, data: bytes) -> bytes:
        """Decompress zstd data with a strict limit of the result size.

        Args:
            limit: maximum size of the decompressed data in bytes (inclusive)
            data: zstd compressed data

        Returns:
            decompressed data, may be empty or partial if the frame is truncated

        Raises:
            ZstdScannerException: the decompressed size is over the limit (declared or actual);
                Python 3.14+: also if the limit does not fit the range of the window size
            zstd.ZstdError: the data are broken, or the frame needs a window bigger than the limit,
                or (Python 3.11-3.13) the limit is less than 1 KiB, the minimal window of zstd

        Note:
            The size declared in the frame header is not trusted: the result is counted while decompressing.
            Peak memory may be a few times bigger than the limit (window, result and its copy).
            Several frames in a row: Python 3.11-3.13 decompresses all of them, Python 3.14+ only the first.
        """
        if sys.version_info < (3, 14):
            # todo: remove when Python 3.11, 3.12, 3.13 support ends
            size = zstd.frame_content_size(data)  # -1 if the size is not declared, the first frame only
            if limit < size:
                # reject at once, before any memory is allocated for the frame
                raise ZstdScannerException(f"Declared size {size} is over limit {limit}")
            ctx = zstd.ZstdDecompressor(max_window_size=limit)
            result = bytearray()
            with ctx.stream_reader(data) as reader:
                while True:
                    # the chunk size is the max excess over the limit which can be allocated before the check
                    if chunk := reader.read(655360):
                        result += chunk
                        if limit < len(result):
                            raise ZstdScannerException(f"Decompression size {len(result)} is over limit {limit}")
                    else:
                        break
            return bytes(result)
        # Python 3.14+: built-in compression.zstd
        lower, upper = zstd.DecompressionParameter.window_log_max.bounds()
        # a frame with a window bigger than 2 ** log_limit is rejected by the decoder
        log_limit = int.bit_length(limit)
        if not lower <= log_limit <= upper:
            raise ZstdScannerException(f"{log_limit} does not fit in range [{lower};{upper}]")
        options: Mapping[int, int] = {zstd.DecompressionParameter.window_log_max: log_limit}
        # one extra byte allows to detect the excess, otherwise the result would be silently cut to the limit
        # only the first frame is decompressed, the rest of the data is ignored
        result = zstd.ZstdDecompressor(options=options).decompress(data, max_length=limit + 1)
        if limit < len(result):
            raise ZstdScannerException(f"Decompression size {len(result)} is over limit {limit}")
        return result

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Decompress data from zstd archive and launch recursive_scan for the result"""
        try:
            if data_provider.file_type.endswith(".zst"):
                file_type = data_provider.file_type[:-4]
            elif data_provider.file_type.endswith(".tzst"):
                # .tar.zst synonym
                file_type = data_provider.file_type[:-5]
            else:
                file_type = data_provider.file_type
            if decompressed := ZstdScanner.decompress(recursive_limit_size, data_provider.data):
                zstd_content_provider = DataContentProvider(data=decompressed,
                                                            file_path=data_provider.file_path,
                                                            file_type=file_type,
                                                            info=f"{data_provider.info}|ZSTD")
                zstd_candidates = self.recursive_scan(zstd_content_provider, depth, recursive_limit_size)
                return zstd_candidates
        except ZstdScannerException as exc:
            logger.debug("%s:%s", exc, data_provider.descriptor)
            # return empty list to avoid extra fallback scan
            return []
        except Exception as exc:  # pylint: disable=broad-exception-caught
            # fallback
            logger.warning("%s:%s:%s", type(exc), exc, data_provider.descriptor)
        return None
