from regex import regex

from credsweeper.credentials import LineData
from credsweeper.filters import Filter
from credsweeper.utils import Util


class ValueAllowlistCheck(Filter):
    """Check that patterns from the list is not present in the candidate value."""

    ALLOWED = [
        "ENC\\(.*\\)", "ENC\\[.*\\]", "\\$\\{.*\\}", "#\\{.*\\}", "\\{\\{.+\\}\\}", "(\\w|\\d|\\.|->)+\\(.*\\)",
        "\\*\\*\\*\\*\\*"
    ]
    ALLOWED_PATTERN = regex.compile(Util.get_regex_combine_or(ALLOWED), flags=regex.IGNORECASE)

    def run(self, line_data: LineData) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data

        Return:
            True, if need to filter candidate and False if left

        """
        if line_data.value is None:
            return True

        if self.ALLOWED_PATTERN.match(line_data.value):
            return True

        return False
