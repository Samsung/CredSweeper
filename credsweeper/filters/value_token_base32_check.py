from typing import Tuple

from credsweeper.filters.value_token_base_check import ValueTokenBaseCheck


class ValueTokenBase32Check(ValueTokenBaseCheck):
    """Check that candidate have good randomization"""

    RANGE_DICT = {
        8: ((3.480934, 0.8482364556537906), (1.9280820731422028, 0.5833143826506801)),
        10: ((3.4801753333333334, 0.7508676237320747), (1.9558544090983234, 0.5119385414964345)),
        15: ((3.4803549285714284, 0.603220270918794), (1.9896690734372564, 0.40640877687972476)),
        16: ((3.4798649333333334, 0.5837818960141307), (1.9938368543943692, 0.392547066949958)),
        20: ((3.4809878947368422, 0.518785674729997), (2.0058661928593517, 0.34692788889724946)),
        24: ((3.480511086956522, 0.4726670109337228), (2.0131379532992537, 0.31476354168931936)),
        25: ((3.480877375, 0.4626150412368404), (2.0147828593929953, 0.3075894753390553)),
        32: ((3.4809023548387095, 0.4072672632996217), (2.0231609118646867, 0.2700344059876962)),
        40: ((3.4801929743589746, 0.36361457820793436), (2.027858606807074, 0.2401498396303172)),
        50: ((3.4798551224489795, 0.323708167297437), (2.0318808048208794, 0.2138098551294688)),
        64: ((3.4805990476190476, 0.28572156450556774), (2.035756800745673, 0.18815721535870078)),
    }

    @staticmethod
    def get_stat_range(size: int) -> Tuple[Tuple[float, float], Tuple[float, float]]:
        """Returns minimal, maximal for hop and deviation. Precalculated data is applied for speedup"""
        if result := ValueTokenBase32Check.RANGE_DICT.get(size):
            ppf = ValueTokenBaseCheck.get_ppf(size)
            return ((result[0][0] - ppf * result[0][1], result[0][0] + ppf * result[0][1]),
                    (result[1][0] - ppf * result[1][1], result[1][0] + ppf * result[1][1]))
        else:
            # not calculated
            raise ValueError
