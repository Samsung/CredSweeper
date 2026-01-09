from typing import Optional

from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters.filter import Filter


class ValueSearchCheck(Filter):
    """Check whether a candidate value contains a pattern - useful for multi rules"""

    def __init__(self, config: Optional[Config] = None, pattern: Optional[str] = None) -> None:
        self.pattern = pattern

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, if need to filter candidate and False if left

        """
        if self.pattern and line_data.value:
            if len(self.pattern) < len(line_data.value):
                if self.pattern in line_data.value:
                    return True
            else:
                if line_data.value in self.pattern:
                    return True
        return False
