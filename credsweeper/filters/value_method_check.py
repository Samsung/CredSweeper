import re
from typing import Optional

from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters.filter import Filter


class ValueMethodCheck(Filter):
    """Check if potential candidate value is a function.

    Check if potential candidate value is a function by looking for '(', ')' or 'function' sub-strings in it
    """

    PATTERN = re.compile(r"^[~.\->:0-9A-Za-z_]+\(.*\)")

    def __init__(self, config: Optional[Config] = None) -> None:
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
        if "function" in line_data.value or self.PATTERN.search(line_data.value):
            return True
        return False
