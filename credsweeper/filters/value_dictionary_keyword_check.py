from credsweeper.common import KeywordChecklist
from credsweeper.credentials import LineData
from credsweeper.filters import Filter


class ValueDictionaryKeywordCheck(Filter):
    """Check that no word from dictionary present in the candidate value."""

    def __init__(self) -> None:
        self.keyword_checklist = KeywordChecklist()

    def run(self, line_data: LineData) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data

        Return:
            True, if need to filter candidate and False if left

        """
        if line_data.value is None:
            return True
        if any(keyword in line_data.value.lower() for keyword in self.keyword_checklist.get_list()):
            return True
        return False
