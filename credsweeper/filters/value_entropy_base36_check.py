import math

from credsweeper.common.constants import Chars
from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter
from credsweeper.utils import Util


class ValueEntropyBase36Check(Filter):
    """Check that candidate have Shanon Entropy (for [a-z0-9])"""

    def __init__(self, config: Config = None) -> None:
        pass

    @staticmethod
    def get_min_data_entropy(x: int) -> float:
        """Returns minimal entropy for size of random data. Precalculated data is applied for speedup"""
        if 15 == x:
            y = 3.43
        elif 24 == x:
            y = 3.91
        elif 25 == x:
            y = 3.95
        elif 10 <= x:
            # approximation does not exceed standard deviation
            y = 0.7 * math.log2(x) + 0.7
        else:
            y = 0
        return y

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, if need to filter candidate and False if left

        """
        entropy = Util.get_shannon_entropy(line_data.value, Chars.BASE36_CHARS.value)
        min_entropy = ValueEntropyBase36Check.get_min_data_entropy(len(line_data.value))
        return min_entropy > entropy or 0 == min_entropy
