import math
from functools import cache

from credsweeper.config import Config
from credsweeper.filters.value_entropy_base_check import ValueEntropyBaseCheck


class ValueEntropyBase64Check(ValueEntropyBaseCheck):
    """Check that candidate have Shanon Entropy > 3 (for HEX_CHARS or BASE36_CHARS) or > 4.5 (for BASE64_CHARS)."""

    def __init__(self, config: Config = None) -> None:
        super().__init__(config)

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
