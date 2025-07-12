import contextlib
from abc import abstractmethod
from typing import Optional
from typing import Tuple

from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters.filter import Filter
from credsweeper.utils.hop_stat import HopStat


class ValueTokenBaseCheck(Filter):
    """Check that candidate have good randomization"""

    MUL_DICT = {
        8: 2.61619746,
        10: 2.48685659,
        15: 2.34025271,
        16: 2.32370290,
        20: 2.27614996,
        24: 2.24609586,
        25: 2.24023515,
        32: 2.21025277,
        40: 2.18961571,
        50: 2.17355282,
        64: 2.15981241,
    }

    def __init__(self, config: Optional[Config] = None) -> None:
        self.__hop_stat = HopStat()

    @staticmethod
    @abstractmethod
    def get_stat_range(size: int) -> Tuple[Tuple[float, float], Tuple[float, float]]:
        """Returns minimal strength. Precalculated data is applied for speedup"""
        raise NotImplementedError

    @staticmethod
    def get_ppf(n: int) -> float:
        """Code used to produce the values"""
        # from scipy.stats import t
        # print('\n'.join(f'{n}: {t.ppf(0.9827, n-1):.8f},' for n in [8,10,15,16,20,24,25,32,40,50,64]))
        return ValueTokenBaseCheck.MUL_DICT[n]

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, if need to filter candidate and False if left

        """
        with contextlib.suppress(Exception):
            hop, dev = self.__hop_stat.stat(line_data.value)
            (min_hop, max_hop), (min_dev, max_dev) = self.get_stat_range(len(line_data.value))
            if not (min_hop <= hop <= max_hop and min_dev <= dev <= max_dev):
                return True
        return False
