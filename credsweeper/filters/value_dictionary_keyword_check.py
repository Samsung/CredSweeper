from credsweeper.common import static_keyword_checklist
from credsweeper.credentials import LineData
from credsweeper.filters import Filter


class ValueDictionaryKeywordCheck(Filter):
    """Check that no word from dictionary present in the candidate value."""

    def run(self, line_data: LineData) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data

        Return:
            True, if need to filter candidate and False if left

        """
        if not line_data.value:
            return True
        line_data_value_lower = line_data.value.lower()
        for keyword in static_keyword_checklist.keyword_set:
            if keyword in line_data_value_lower:
                return True
        return False
