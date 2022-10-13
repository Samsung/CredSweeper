from regex import regex

from credsweeper.credentials import LineData
from credsweeper.filters import Filter
from credsweeper.utils import Util


class ValueNotAllowedPatternCheck(Filter):
    """Check that secret doesn't open or closes brackets or a new line."""

    NOT_ALLOWED = ["[,<>{};\\]\\[](\\s)*", "(\\s)+[\\\\]", "(\\\\n)(\\s)*"]
    NOT_ALLOWED_PATTERN = regex.compile(f"{Util.get_regex_combine_or(NOT_ALLOWED)}$", flags=regex.IGNORECASE)

    def run(self, line_data: LineData) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data

        Return:
            True, if need to filter candidate and False if left

        """
        if line_data.value is None:
            return True
        if self.NOT_ALLOWED_PATTERN.search(line_data.value):
            return True
        return False
