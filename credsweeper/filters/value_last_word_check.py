from regex import regex

from credsweeper.credentials import LineData
from credsweeper.filters import Filter


class ValueLastWordCheck(Filter):
    """Check that secret is not short value that ends with `:`."""

    NOT_ALLOWED_COLON_PATTERN = regex.compile(".*:$", flags=regex.IGNORECASE)

    def run(self, line_data: LineData) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data

        Return:
            True, if need to filter candidate and False if left

        """
        if line_data.value is None:
            return True
        if len(line_data.value) < 16 and self.NOT_ALLOWED_COLON_PATTERN.search(line_data.value):
            return True
        return False
