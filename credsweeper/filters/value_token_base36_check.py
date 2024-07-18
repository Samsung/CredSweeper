from password_strength import PasswordStats

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter


class ValueTokenBase36Check(Filter):
    """Check that candidate have good randomization"""

    def __init__(self, config: Config = None) -> None:
        pass

    @staticmethod
    def get_min_strength(x: int) -> float:
        """Returns minimal strength. Precalculated data is applied for speedup"""
        if 15 == x:
            y = 0.66
        elif 24 == x:
            y = 0.9
        elif 25 == x:
            y = 0.9
        elif 8 <= x <= 32:
            # approximation not exceed standard deviation
            y = ((0.000067 * x - 0.00571) * x + 0.1718) * x - 0.86
        else:
            y = 1
        return y

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, if need to filter candidate and False if left

        """

        strength = float(PasswordStats(line_data.value).strength())
        min_strength = ValueTokenBase36Check.get_min_strength(len(line_data.value))
        return min_strength > strength
