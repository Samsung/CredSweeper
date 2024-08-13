import re

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter


class ValueArrayDictionaryCheck(Filter):
    """Match call to dictionary or array element.

    This filter checks only calls, not declarations:
        `token = values[i]` would be filtered
        `token = {'root'}` would be kept
    """

    PATTERN = re.compile(r"\[('|\")?.+('|\")?\]")

    def __init__(self, config: Config = None) -> None:
        pass

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, if need to filter candidate and False if left

        """
        if line_data.is_well_quoted_value:
            return False
        if self.PATTERN.search(line_data.value):
            return True
        if line_data.wrap and not line_data.is_well_quoted_value and ('[' in line_data.wrap or '(' in line_data.wrap):
            return True

        return False
