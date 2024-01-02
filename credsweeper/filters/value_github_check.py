import binascii
import contextlib

import base62

from credsweeper.common.constants import ASCII
from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter


class ValueGitHubCheck(Filter):
    """GitHub Classic Token validation"""

    def __init__(self, config: Config = None) -> None:
        pass

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received token which might be structured.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, when need to filter candidate and False if left

        """
        # https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/
        if not line_data.value:
            return True
        with contextlib.suppress(Exception):
            if line_data.value.startswith("gh") and '_' == line_data.value[3]:
                token = line_data.value[4:-6]
                data = token.encode(ASCII, errors="strict")
                crc32sum = binascii.crc32(data)
                base62_crc32 = line_data.value[-6:]
                sign_b = base62.decodebytes(base62_crc32)
                crc32sign = int.from_bytes(sign_b, "big")
                if crc32sign == crc32sum:
                    return False
        return True
