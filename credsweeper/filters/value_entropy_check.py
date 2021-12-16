from credsweeper.credentials import LineData
from credsweeper.filters import Filter
from credsweeper.utils import Util


class ValueEntropyCheck(Filter):
    """Check that candidate have Shanon Entropy > 3 (for HEX_CHARS or BASE36_CHARS) or > 4.5 (for BASE64_CHARS)."""

    def run(self, line_data: LineData) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data

        Return:
            True, if need to filter candidate and False if left

        """
        if line_data.value is None:
            return True
        return not Util.is_entropy_validate(line_data.value)
