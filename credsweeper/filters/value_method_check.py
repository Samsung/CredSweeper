from regex import regex

from credsweeper.credentials import LineData
from credsweeper.filters import Filter


class ValueMethodCheck(Filter):
    """Check if potential candidate value is a function.

    Check if potential candidate value is a function by looking for '(', ')' or 'function' sub-strings in it
    """

    PATTERN = regex.compile(".*\\(.*\\).*")

    def run(self, line_data: LineData) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data

        Return:
            True, if need to filter candidate and False if left

        """
        if line_data.value is None:
            return True
        if "function" in line_data.value or self.PATTERN.search(line_data.value):
            return True
        return False
