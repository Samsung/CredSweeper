import re

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter
from credsweeper.utils import Util


class ValueFirstWordCheck(Filter):
    """Check that secret doesn't starts with special character."""

    NOT_ALLOWED = [
        r"\=", r"\{", r"\)", r"\<", r"\>", r"\#", r"\:", r"\\\\", r"\\/\\/", r"\_", r"\/\*", r"\%[deflspuvxz]"
    ]
    NOT_ALLOWED_PATTERN = re.compile(  #
        f"^{Util.get_regex_combine_or(NOT_ALLOWED)}",  #
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
        if line_data.is_well_quoted_value:
            return False
        if self.NOT_ALLOWED_PATTERN.match(line_data.value):
            return True
        return False
