from typing import List

from credsweeper.credentials import LineData
from credsweeper.filters import Filter


class ValueDictionaryKeywordCheck(Filter):
    """Check that no word from dictionary present in the candidate value."""

    def __init__(self, keyword_checklist: List[str]) -> None:
        self.__keyword_checklist = keyword_checklist

    def run(self, line_data: LineData) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data

        Return:
            True, if need to filter candidate and False if left

        """
        if line_data.value is None:
            return True
        if any(keyword in line_data.value.lower() for keyword in self.__keyword_checklist):
            return True
        return False
