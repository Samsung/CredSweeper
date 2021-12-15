from regex import regex

from credsweeper.credentials import LineData
from credsweeper.filters import Filter


class ValueArrayDictionaryCheck(Filter):
    """Match call to dictionary or array element.

    This filter checks only calls, not declarations:
        `token = values[i]` would be filtered
        `token = {'root'}` would be kept
    """

    PATTERN = regex.compile("\\[('|\")?.+('|\")?\\]")

    def run(self, line_data: LineData) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data

        Return:
            True, if need to filter candidate and False if left

        """
        if line_data.value is None:
            return True

        if self.PATTERN.search(line_data.value):
            return True

        return False
