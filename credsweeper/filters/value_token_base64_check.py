from typing import Tuple

from credsweeper.filters.value_token_base_check import ValueTokenBaseCheck


class ValueTokenBase64Check(ValueTokenBaseCheck):
    """Check that candidate have good randomization"""

    RANGE_DICT = {
        8: ((3.7627115714285715, 0.9413431166706269), (2.1378378843992736, 0.6394596814295781)),
        10: ((3.7617393333333333, 0.8327986018456262), (2.168873183866972, 0.5605393324056347)),
        15: ((3.7619624285714286, 0.6698092646328063), (2.2080058406286702, 0.4447698491992352)),
        16: ((3.7618573333333334, 0.6471500119793832), (2.2116826642934453, 0.4288377928263507)),
        20: ((3.7618887368421055, 0.575813792926031), (2.224384985667721, 0.37985781543221253)),
        24: ((3.7621449565217393, 0.5243297908608613), (2.2326041329976607, 0.34397389723600613)),
        25: ((3.762616791666667, 0.5137934920050976), (2.234571917211925, 0.3366547036535176)),
        32: ((3.761885838709677, 0.4521158322065318), (2.2426375800006153, 0.29506039075960255)),
        40: ((3.7622649487179487, 0.4031261511824518), (2.2485911621253574, 0.2622954601051068)),
        50: ((3.762087693877551, 0.3597404118023357), (2.2533774423872956, 0.23384524947332655)),
        64: ((3.7625271746031745, 0.31733579704946846), (2.257532519514275, 0.20571908142867643)),
    }

    @staticmethod
    def get_stat_range(size: int) -> Tuple[Tuple[float, float], Tuple[float, float]]:
        """Returns minimal, maximal for hop and deviation. Precalculated data is applied for speedup"""
        if result := ValueTokenBase64Check.RANGE_DICT.get(size):
            ppf = ValueTokenBaseCheck.get_ppf(size)
            return ((result[0][0] - ppf * result[0][1], result[0][0] + ppf * result[0][1]),
                    (result[1][0] - ppf * result[1][1], result[1][0] + ppf * result[1][1]))
        else:
            # not calculated
            raise ValueError
