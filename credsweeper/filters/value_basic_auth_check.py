import contextlib
from typing import Optional

from credsweeper.common.constants import DEFAULT_PATTERN_LEN, UTF_8
from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters.filter import Filter
from credsweeper.utils.util import Util


class ValueBasicAuthCheck(Filter):
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
        value = line_data.value
        with contextlib.suppress(Exception):
            # Basic encoding -> login:password
            decoded = Util.decode_base64(value, padding_safe=True, urlsafe_detect=True)
            delimiter_pos = decoded.find(b':')
            # check whether the delimiter exists and all chars are decoded
            if 0 < delimiter_pos < len(decoded) - DEFAULT_PATTERN_LEN and decoded.decode(UTF_8):
                return False
        return True
