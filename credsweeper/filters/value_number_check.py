import re
from typing import Optional

from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters.filter import Filter


class ValueNumberCheck(Filter):
    """Check value if it a value in hex or decimal representation"""

    HEX_VALUE_REGEX = re.compile("^(0x)?[0-9a-f]{1,128}[ul]{0,3}$")
    DEC_VALUE_REGEX = re.compile("^-?[0-9]{1,20}[ul]{0,3}$")

    def __init__(self, config: Optional[Config] = None) -> None:
        pass

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, if need to filter candidate and False if left

        """
        value = line_data.value.lower()
        if 22 > len(value) and ValueNumberCheck.HEX_VALUE_REGEX.match(value):
            return True
        if ValueNumberCheck.DEC_VALUE_REGEX.match(value):
            return True
        return False
