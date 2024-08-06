import math

from credsweeper.common.constants import Chars, ENTROPY_LIMIT_BASE64
from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter
from credsweeper.utils import Util


class ValueEntropyBase64Check(Filter):
    """Check that candidate have Shanon Entropy > 3 (for HEX_CHARS or BASE36_CHARS) or > 4.5 (for BASE64_CHARS)."""

    def __init__(self, config: Config = None) -> None:
        pass

    @staticmethod
    def get_min_data_entropy(x: int) -> float:
        """Returns minimal average entropy for size of random data. Precalculated round data is applied for speedup"""
        if 18 == x:
            y = 3.8
        elif 20 == x:
            y = 3.9
        elif 24 == x:
            y = 4.1
        elif 32 == x:
            y = 4.4
        elif 12 <= x < 35:
            # logarithm base 2 - slow, but precise. Approximation does not exceed stdev
            y = 0.77 * math.log2(x) + 0.62
        elif 35 <= x < 60:
            y = ENTROPY_LIMIT_BASE64
        elif 60 <= x:
            # the entropy grows slowly after 60
            y = 5.0
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
        if '-' in line_data.value or '_' in line_data.value:
            entropy = Util.get_shannon_entropy(line_data.value, Chars.BASE64URL_CHARS.value)
        else:
            entropy = Util.get_shannon_entropy(line_data.value, Chars.BASE64STD_CHARS.value)
        min_entropy = ValueEntropyBase64Check.get_min_data_entropy(len(line_data.value))
        return min_entropy > entropy or 0 == min_entropy
