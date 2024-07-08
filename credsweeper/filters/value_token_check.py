import re

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter


class ValueTokenCheck(Filter):
    """Check if first substring of token is shorter than 5.

    Split candidate value into substrings using ` ;`{})(<>[]` separators. Check if first substring is shorter than 5

    Examples:
        "my password"
        "12);password"

    """

    SPLIT_PATTERN = r" |;|\)|\(|{|}|<|>|\[|\]|`"

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
        tokens = re.split(self.SPLIT_PATTERN, line_data.value, maxsplit=1)
        # If tokens have length of 1 - pattern is not present in the value and original value returned from `.split(`
        if len(tokens) < 2:
            return False

        token = tokens[0]
        if len(token) < 5:
            return True

        return False
