from regex import regex

from credsweeper.credentials import LineData
from credsweeper.filters import Filter
from credsweeper.utils import Util


class ValueUselessWordCheck(Filter):
    """Check is candidate value contains sub-rows with operators (like ->)."""

    NOT_ALLOWED = [
        "((\\{)?(0x)+([0-9a-f]|\\%){1}.*)",  # Check is contain \{0x or 0x
        "(\\-\\>.*)",  # Check if contain ->
        "(xxxx.*)",  # Check if contain xxxxx
        "(\\s).*"  # Check if contain \s
    ]
    NOT_ALLOWED_PATTERN = regex.compile(Util.get_regex_combine_or(NOT_ALLOWED), flags=regex.IGNORECASE)

    def run(self, line_data: LineData) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data

        Return:
            True, if need to filter candidate and False if left

        """
        if line_data.value is None:
            return True

        if self.NOT_ALLOWED_PATTERN.match(line_data.value):
            return True

        return False
