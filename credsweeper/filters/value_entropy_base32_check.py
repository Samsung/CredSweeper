import math
from functools import cache

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter
from credsweeper.filters.value_entropy_base_check import ValueEntropyBaseCheck
from credsweeper.utils import Util


class ValueEntropyBase32Check(ValueEntropyBaseCheck):
    """Check that candidate have Shanon Entropy (for [a-z0-9])"""

    def __init__(self, config: Config = None) -> None:
        super().__init__(config)

    @staticmethod
    @cache
    def get_min_data_entropy(x: int) -> float:
        """Returns average entropy for size of random data. Precalculated data is applied for speedup"""
        if 8 <= x < 17:
            y = 0.80569236 * math.log2(x) + 0.13439734
        elif 17 <= x < 33:
            y = 0.66350481 * math.log2(x) + 0.71143862
        elif 33 <= x:
            y = 4.04
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
        entropy = Util.get_shannon_entropy(line_data.value)
        min_entropy = ValueEntropyBase32Check.get_min_data_entropy(len(line_data.value))
        if min_entropy > entropy or 0 == min_entropy:
            return True
        return False
