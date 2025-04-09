import math
from functools import cache

from credsweeper.filters.value_entropy_base_check import ValueEntropyBaseCheck


class ValueEntropyBase36Check(ValueEntropyBaseCheck):
    """Base36 entropy check"""

    @staticmethod
    @cache
    def get_min_data_entropy(x: int) -> float:
        """Returns minimal entropy for size of random data. Precalculated data is applied for speedup"""
        if 15 == x:
            # workaround for Dropbox App secret
            y = 3.374
        elif 10 <= x < 26:
            y = 0.731566857 * math.log2(x) + 0.474132
        elif 26 <= x:
            y = 3.9
        else:
            y = 0
        return y
