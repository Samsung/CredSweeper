import math
from functools import cache

from credsweeper.filters.value_entropy_base_check import ValueEntropyBaseCheck


class ValueEntropyBase64Check(ValueEntropyBaseCheck):
    """Base64 entropy check"""

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
        elif 256 <= x:
            y = 6 - 64 / x
        else:
            y = 0
        return y
