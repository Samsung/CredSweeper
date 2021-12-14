from regex import regex

from credsweeper.credentials import LineData
from credsweeper.filters import Filter
from credsweeper.utils import Util


class ValueCamelCaseCheck(Filter):
    """Check that candidate is not written in camel case."""

    CAMEL_CASE = ["^([a-z]+([A-Z][a-z]+)+)$", "^([A-Z][a-z]+([A-Z][a-z]+)+)$"]
    CAMEL_CASE_PATTERN = regex.compile(Util.get_regex_combine_or(CAMEL_CASE))

    def run(self, line_data: LineData) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data

        Return:
            True, if need to filter candidate and False if left

        """
        if line_data.value is None:
            return True

        if self.CAMEL_CASE_PATTERN.match(line_data.value):
            return True

        return False
