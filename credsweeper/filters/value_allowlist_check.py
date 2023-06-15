import re

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter
from credsweeper.utils import Util


class ValueAllowlistCheck(Filter):
    """Check that patterns from the list is not present in the candidate value."""

    ALLOWED = [
        "ENC\\(.*\\)", "ENC\\[.*\\]", "\\$\\{.*\\}", "#\\{.*\\}", "\\{\\{.+\\}\\}", "([.a-z0-9]|->)+\\(.*\\)",
        "\\*\\*\\*\\*\\*"
    ]
    ALLOWED_PATTERN = re.compile(  #
        Util.get_regex_combine_or(ALLOWED),  #
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
        if not line_data.value:
            return True

        if self.ALLOWED_PATTERN.match(line_data.value):
            return True

        return False
