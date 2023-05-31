from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.filters import Filter


class ValueLengthCheck(Filter):
    """Check if potential candidate value is not too short (longer or equal to `min_len`)."""

    def __init__(self, config: Config) -> None:
        self.min_len = config.min_keyword_value_length

    def run(self, line_data: LineData) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data

        Return:
            True, if need to filter candidate and False if left

        """
        if not line_data.value:
            return True
        if len(line_data.value) < self.min_len:
            return True
        return False
