from abc import abstractmethod
from typing import Optional

from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters.filter import Filter
from credsweeper.utils.util import Util


class ValueEntropyBaseCheck(Filter):
    """Check that candidate value has minimal Shanon Entropy for appropriated base"""

    def __init__(self, config: Optional[Config] = None) -> None:
        pass

    @staticmethod
    @abstractmethod
    def get_min_data_entropy(x: int) -> float:
        """Returns minimal entropy for size of data"""
        raise NotImplementedError()

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, when need to filter candidate and False if left

        """
        entropy = Util.get_shannon_entropy(line_data.value)
        min_entropy = self.get_min_data_entropy(len(line_data.value))
        if min_entropy > entropy or 0 == min_entropy:
            return True
        return False
