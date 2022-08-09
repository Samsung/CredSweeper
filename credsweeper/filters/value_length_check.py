from credsweeper.credentials import LineData
from credsweeper.filters import Filter


class ValueLengthCheck(Filter):
    """Check if potential candidate value is not too short (longer or equal to `min_len`)."""

    def __init__(self, min_len) -> None:
        self.min_len = min_len

    def run(self, line_data: LineData) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data

        Return:
            True, if need to filter candidate and False if left

        """
        if line_data.value is None:
            return True
        if len(line_data.value) < self.min_len:
            return True
        return False
