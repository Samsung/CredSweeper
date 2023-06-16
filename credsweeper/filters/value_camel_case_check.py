import re

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter
from credsweeper.utils import Util


class ValueCamelCaseCheck(Filter):
    """Check that candidate is not written in camel case."""

    CAMEL_CASE = ["^([a-z]+([A-Z][a-z]+)+)$", "^([A-Z][a-z]+([A-Z][a-z]+)+)$"]
    CAMEL_CASE_PATTERN = re.compile(Util.get_regex_combine_or(CAMEL_CASE))

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

        if self.CAMEL_CASE_PATTERN.match(line_data.value):
            return True

        return False
