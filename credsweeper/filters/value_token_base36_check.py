from typing import Tuple

from credsweeper.filters.value_token_base_check import ValueTokenBaseCheck


class ValueTokenBase36Check(ValueTokenBaseCheck):
    """Check that candidate have good randomization"""

    RANGE_DICT = {
        8: ((3.7190542428571427, 0.8995506118495411), (2.066095086865182, 0.609210293352161)),
        10: ((3.719109611111111, 0.7956463384852813), (2.0946299036665494, 0.5322004874842623)),
        15: ((3.719274257142857, 0.6401989313894239), (2.129437216268589, 0.42108786288993155)),
        16: ((3.7192072666666665, 0.6188627491757901), (2.1336109506109366, 0.4064699817331141)),
        20: ((3.719249815789474, 0.5506473627709657), (2.145293932511567, 0.3591543917048417)),
        24: ((3.7191934304347827, 0.50051922802262), (2.152858549996053, 0.3252064160191062)),
        25: ((3.7192351583333334, 0.4904181410613897), (2.1543202565038735, 0.31823801389315026)),
        32: ((3.7190408419354837, 0.4315967526660196), (2.1620321219700767, 0.2788634701820312)),
        40: ((3.7191682666666668, 0.3852248727988986), (2.16746680811131, 0.24802261318501675)),
        50: ((3.718913744897959, 0.3436564880405547), (2.1715676118603806, 0.22070510537297627)),
        64: ((3.7190009761904763, 0.30325954360127116), (2.1751172797904093, 0.1942582237461476)),
    }

    @staticmethod
    def get_stat_range(size: int) -> Tuple[Tuple[float, float], Tuple[float, float]]:
        """Returns minimal, maximal for hop and deviation. Precalculated data is applied for speedup"""
        if result := ValueTokenBase36Check.RANGE_DICT.get(size):
            ppf = ValueTokenBaseCheck.get_ppf(size)
            return ((result[0][0] - ppf * result[0][1], result[0][0] + ppf * result[0][1]),
                    (result[1][0] - ppf * result[1][1], result[1][0] + ppf * result[1][1]))
        else:
            # not calculated
            raise ValueError
