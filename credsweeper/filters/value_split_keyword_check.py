from credsweeper.common import KeywordChecklist
from credsweeper.credentials import LineData
from credsweeper.filters import Filter


class ValueSplitKeywordCheck(Filter):
    """Check value by splitting with standard whitespace separators and any word is not matched in checklist."""

    def __init__(self) -> None:
        """ValueSplitKeywordCheck constructor"""
        self.keyword_checklist = KeywordChecklist()

    def run(self, line_data: LineData) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data

        Return:
            True, if need to filter candidate and False if left

        """
        if not line_data.value:
            return True
        words = line_data.value.lower().split()
        if any(keyword in words for keyword in self.keyword_checklist.get_list()):
            return True
        return False
