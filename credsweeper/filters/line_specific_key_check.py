from regex import regex

from credsweeper.credentials import LineData
from credsweeper.filters import Filter
from credsweeper.utils import Util


class LineSpecificKeyCheck(Filter):
    """Check that values from list below is not in candidate line."""

    NOT_ALLOWED = ["example", "enc\\(", "enc\\[", "true", "false"]
    NOT_ALLOWED_PATTERN = regex.compile(Util.get_regex_combine_or(NOT_ALLOWED), flags=regex.IGNORECASE)

    def run(self, line_data: LineData) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data

        Return:
            True, if need to filter candidate and False if left

        """
        if line_data.line is None:
            return True

        if self.NOT_ALLOWED_PATTERN.search(line_data.line):
            return True

        return False
