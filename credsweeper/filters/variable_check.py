from regex import regex

from credsweeper.credentials import LineData
from credsweeper.filters import Filter
from credsweeper.utils import Util


class VariableCheck(Filter):
    """Check if candidate variable is a regex placeholder or ends with match character (like + or >)."""

    NOT_ALLOWED = ["^([<]|\\{\\{).*", "(\\@.*)", "[!><+*/^|)](\\s)?$"]
    NOT_ALLOWED_PATTERN = regex.compile(Util.get_regex_combine_or(NOT_ALLOWED), flags=regex.IGNORECASE)

    def run(self, line_data: LineData) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data

        Return:
            True, if need to filter candidate and False if left

        """
        if line_data.variable is None:
            return True

        if self.NOT_ALLOWED_PATTERN.match(line_data.variable):
            return True

        return False
