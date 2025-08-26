import re
from typing import Optional

from credsweeper.common import static_keyword_checklist
from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters.filter import Filter
from credsweeper.utils.util import Util


class ValueCamelCaseCheck(Filter):
    """Check that candidate is not written in camel case."""

    CAMEL_CASE = ["[a-z]+([A-Z][a-z]+)+", "[A-Z][a-z]+([A-Z][a-z]+)+"]
    CAMEL_CASE_PATTERN = re.compile(Util.get_regex_combine_or(CAMEL_CASE))

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
        if self.CAMEL_CASE_PATTERN.fullmatch(line_data.value):
            return static_keyword_checklist.check_morphemes(line_data.value.lower(), 1)

        return False
