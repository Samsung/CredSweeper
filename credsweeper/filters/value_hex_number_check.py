import re

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter


class ValueHexNumberCheck(Filter):
    """Check value if it a value in 32 or 64 bits hex representation"""

    HEX_32_64_VALUE_REGEX = re.compile(r"^0x([0-9a-f]{8}){1,2}$")

    def __init__(self, config: Config = None) -> None:
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
        if len(value) in [10, 18] and ValueHexNumberCheck.HEX_32_64_VALUE_REGEX.match(value):
            return True
        return False
