from typing import Optional

from credsweeper.common.constants import MIN_VALUE_LENGTH, MAX_LINE_LENGTH
from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters.filter import Filter


class ValueLengthCheck(Filter):
    """Check that candidate value length is between MIN and MAX."""

    def __init__(self,
                 config: Optional[Config] = None,
                 min_len: int = MIN_VALUE_LENGTH,
                 max_len: int = MAX_LINE_LENGTH) -> None:
        self.min_len = min_len
        self.max_len = max_len

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, if need to filter candidate and False if left

        """
        if self.min_len <= len(line_data.value) <= self.max_len:
            return False
        else:
            return True
