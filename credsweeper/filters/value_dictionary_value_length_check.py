from credsweeper.credentials import LineData
from credsweeper.filters import Filter


class ValueDictionaryValueLengthCheck(Filter):
    """Check that candidate length is between 5 and 30."""

    def run(self, line_data: LineData) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data

        Return:
            True, if need to filter candidate and False if left

        """
        if line_data.value is None:
            return True
        if len(line_data.value) < 4 or len(line_data.value) > 30:
            return True
        return False
