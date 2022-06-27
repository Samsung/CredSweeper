from credsweeper.credentials import LineData
from credsweeper.filters import Filter


class ValueAsciiCheck(Filter):
    """Check value is consist of ascii code."""

    def run(self, line_data: LineData) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data

        Return:
            True, if need to filter candidate and False if left

        """
        if not line_data.value.isascii():
            return True

        return False
