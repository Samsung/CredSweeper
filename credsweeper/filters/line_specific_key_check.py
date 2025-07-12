import re
from typing import Optional

from credsweeper.common.constants import ML_HUNK
from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters.filter import Filter
from credsweeper.utils.util import Util


class LineSpecificKeyCheck(Filter):
    """Check that values from list below is not in candidate line."""

    NOT_ALLOWED = [r"example", r"\benc[\(\[]", r"\btrue\b", r"\bfalse\b"]
    NOT_ALLOWED_PATTERN = re.compile(Util.get_regex_combine_or(NOT_ALLOWED), re.IGNORECASE)

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
        if line_data.line is None:
            return True
        if 0 <= line_data.variable_start:
            # variable may be defined too
            sub_line_start = 0 if ML_HUNK >= line_data.variable_start else line_data.variable_start - ML_HUNK
        else:
            sub_line_start = 0 if ML_HUNK >= line_data.value_start else line_data.value_start - ML_HUNK

        if self.NOT_ALLOWED_PATTERN.search(line_data.line, sub_line_start, line_data.value_end + ML_HUNK):
            return True

        return False
