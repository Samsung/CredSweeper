from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter


class ValueDictionaryValueLengthCheck(Filter):
    """Check that candidate length is between 5 and 30."""

    def __init__(self, config: Config = None, min_len: int = 4, max_len: int = 31) -> None:
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
