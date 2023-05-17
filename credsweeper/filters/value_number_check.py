import regex

from credsweeper.credentials import LineData
from credsweeper.filters import Filter


class ValueNumberCheck(Filter):
    """Check value if it a value in hex or decimal representation"""

    HEX_VALUE_REGEX = regex.compile("^0x[0-9a-f]+[ul]*$")
    DEC_VALUE_REGEX = regex.compile("^-?[0-9]+$")

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
        if value.startswith("0x") and ValueNumberCheck.HEX_VALUE_REGEX.match(value):
            return True
        if ValueNumberCheck.DEC_VALUE_REGEX.match(value):
            return True
        return False
