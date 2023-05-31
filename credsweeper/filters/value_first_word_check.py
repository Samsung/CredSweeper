from regex import regex

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.filters import Filter
from credsweeper.utils import Util


class ValueFirstWordCheck(Filter):
    """Check that secret doesn't starts with special character."""

    NOT_ALLOWED = [
        "\\=", "\\{", "\\)", "\\<", "\\>", "\\#", "\\:", "\\\\", "\\/\\/", "\\_", "\\\\[u]", "\\/\\*", "\\%[deflspuvxz]"
    ]
    NOT_ALLOWED_PATTERN = regex.compile(  #
        f"^{Util.get_regex_combine_or(NOT_ALLOWED)}",  #
        flags=regex.IGNORECASE)  # pylint: disable=no-member

    def __init__(self, config: Config = None) -> None:
        pass

    def run(self, line_data: LineData) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data

        Return:
            True, if need to filter candidate and False if left

        """
        if not line_data.value:
            return True
        if self.NOT_ALLOWED_PATTERN.match(line_data.value):
            return True
        return False
