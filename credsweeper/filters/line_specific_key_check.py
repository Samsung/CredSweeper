import re

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter
from credsweeper.utils import Util


class LineSpecificKeyCheck(Filter):
    """Check that values from list below is not in candidate line."""

    NOT_ALLOWED = [r"example", r"enc\(", r"enc\[", r"true", r"false"]
    NOT_ALLOWED_PATTERN = re.compile(  #
        Util.get_regex_combine_or(NOT_ALLOWED),  #
        flags=re.IGNORECASE)

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
        if line_data.line is None:
            return True

        if self.NOT_ALLOWED_PATTERN.search(line_data.line):
            return True

        return False
