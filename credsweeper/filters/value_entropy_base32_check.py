import math
from functools import cache

from credsweeper.filters.value_entropy_base_check import ValueEntropyBaseCheck


class ValueEntropyBase32Check(ValueEntropyBaseCheck):
    """Base32 entropy check"""

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
