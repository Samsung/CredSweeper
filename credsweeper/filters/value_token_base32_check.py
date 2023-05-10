from password_strength import PasswordStats

from credsweeper.credentials import LineData
from credsweeper.filters import Filter


class ValueTokenBase32Check(Filter):
    """Check that candidate have good randomization"""

    def run(self, line_data: LineData) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data

        Return:
            True, if need to filter candidate and False if left

        """
        if not line_data.value:
            return True

        stats = PasswordStats(line_data.value)
        return bool(0.7 > stats.strength())
