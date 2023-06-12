import re

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.filters import Filter


class ValueNumberCheck(Filter):
    """Check value if it a value in hex or decimal representation"""

    HEX_VALUE_REGEX = re.compile("^(0x)?[0-9a-f]+[ul]*$")
    DEC_VALUE_REGEX = re.compile("^-?[0-9]+[ul]*$")

    def __init__(self, config: Config = None) -> None:
        pass

    def run(self, line_data: LineData) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data

        Return:
            True, if need to filter candidate and False if left

        """
        if not line_data.value:
            return True
        value = line_data.value.lower()
        if 22 > len(value) and ValueNumberCheck.HEX_VALUE_REGEX.match(value):
            return True
        if ValueNumberCheck.DEC_VALUE_REGEX.match(value):
            return True
        return False
