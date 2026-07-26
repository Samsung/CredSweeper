import contextlib
from typing import Optional

import bech32

from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters.filter import Filter


class ValueBech32Check(Filter):
    """
    Check that candidate is bech32 format
    """

    def __init__(self, config: Optional[Config] = None) -> None:
        pass

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received weird base32 token which must be a random string

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, when need to filter candidate and False if left

        """
        with contextlib.suppress(Exception):
            if decoded := bech32.bech32_decode(line_data.value.lower()):
                return not bool(decoded[0] and decoded[1])
        return True
