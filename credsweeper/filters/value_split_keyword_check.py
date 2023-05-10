from typing import Union

from credsweeper.common import static_keyword_checklist
from credsweeper.credentials import LineData
from credsweeper.filters import Filter


class ValueSplitKeywordCheck(Filter):
    """Check value by splitting with standard whitespace separators and any word is not matched in checklist."""

    def run(self, line_data: LineData) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data

        Return:
            True, if need to filter candidate and False if left

        """
        if not line_data.value:
            return True
        words: Union[set, list] = line_data.value.lower().split()
        if static_keyword_checklist.keyword_len < len(words):
            words = set(words)
        keyword_set = static_keyword_checklist.keyword_set
        if static_keyword_checklist.keyword_len < len(words):
            for keyword in keyword_set:
                if keyword in words:
                    return True
        else:
            for word in words:
                if word in keyword_set:
                    return True
        return False
