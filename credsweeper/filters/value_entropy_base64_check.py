import math
from functools import cache

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter
from credsweeper.utils import Util


class ValueEntropyBase64Check(Filter):
    """Check that candidate have Shanon Entropy > 3 (for HEX_CHARS or BASE36_CHARS) or > 4.5 (for BASE64_CHARS)."""

    # If the value size is less than this value the entropy evaluation gives an imprecise result
    min_length = 12

    def __init__(self, config: Config = None) -> None:
        pass

    @staticmethod
    @cache
    def get_min_data_entropy(x: int) -> float:
        """Returns minimal average entropy for size of random data. Precalculated round data is applied for speedup"""
        if 12 <= x < 18:
            y = 0.915 * math.log2(x) - 0.047
        elif 18 <= x < 35:
            y = 0.767 * math.log2(x) + 0.5677
        elif 35 <= x < 65:
            y = 0.944 * math.log2(x) - 0.009 * x - 0.04
        elif 65 <= x < 256:
            y = 0.621 * math.log2(x) - 0.003 * x + 1.54
        elif 256 <= x < 512:
            y = 5.77
        elif 512 <= x < 1024:
            y = 5.89
        elif 1024 <= x:
            y = 5.94
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
        min_entropy = ValueEntropyBase64Check.get_min_data_entropy(len(line_data.value))
        if min_entropy > entropy or 0 == min_entropy:
            return True
        return False
