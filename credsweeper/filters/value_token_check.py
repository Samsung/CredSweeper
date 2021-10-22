from regex import regex

from credsweeper.credentials import LineData
from credsweeper.filters import Filter


class ValueTokenCheck(Filter):
    """Split candidate value into substrings using ` ;`{})(<>[]` separators. Check if first substring is shorter than 5
    Examples:
        "my password"
        "12);password"
    """
    SPLIT_PATTERN = " |;|\\)|\\(|{|}|<|>|\\[|\\]|`"

    def run(self, line_data: LineData) -> bool:
        """Run filter checks on received credential candidate data 'line_data'

        Args:
            line_data: LineData object, credential candidate data

        Return:
            boolean variable. True, if need to filter candidate and False if left
        """
        if line_data.value is None:
            return True

        tokens = regex.split(self.SPLIT_PATTERN, line_data.value, maxsplit=1)
        # If tokens have length of 1 - pattern is not present in the value and original value returned from `.split(`
        if len(tokens) < 2:
            return False

        token = tokens[0]
        if len(token) < 5:
            return True

        return False
