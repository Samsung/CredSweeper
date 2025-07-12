import binascii
import contextlib
import struct
from typing import Optional

from credsweeper.common.constants import ASCII
from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters.filter import Filter


class ValueGrafanaServiceCheck(Filter):
    """Check that candidate have a known structure"""

    def __init__(self, config: Optional[Config] = None) -> None:
        pass

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received token which might be structured.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, if need to filter candidate and False if left

        """
        with contextlib.suppress(Exception):
            checksum = struct.unpack("<I", bytes.fromhex(line_data.value[38:]))[0]
            data = line_data.value[:37].encode(ASCII)
            crc32 = binascii.crc32(data)
            if checksum == crc32:
                return False
        return True
