from password_strength import PasswordStats

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter


class ValueTokenBase64Check(Filter):
    """Check that candidate have good randomization"""

    def __init__(self, config: Config = None) -> None:
        pass

    @staticmethod
    def get_min_strength(x: int) -> float:
        """Returns minimal strength. Precalculated rounded data is applied for speedup"""
        if 18 == x:
            y = 0.7
        elif 20 == x:
            y = 0.8
        elif 24 == x:
            y = 0.9
        elif 32 == x:
            y = 0.9
        elif x < 40:
            y = ((0.0000405 * x - 0.004117) * x + 0.141) * x - 0.65
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
        min_strength = ValueTokenBase64Check.get_min_strength(len(line_data.value))
        return min_strength > strength
