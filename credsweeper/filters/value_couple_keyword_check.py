from credsweeper.common import static_keyword_checklist
from credsweeper.credentials import LineData
from credsweeper.filters import Filter


class ValueCoupleKeywordCheck(Filter):
    """Check value if TWO words from EXTENDED Keyword checklist exists in value"""

    def run(self, line_data: LineData) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data

        Return:
            True, if need to filter candidate and False if left

        """
        if not line_data.value:
            return True
        value = line_data.value.lower()
        matches = 0
        for keyword in static_keyword_checklist.morpheme_set:
            if keyword in value:
                matches += 1
                if 1 < matches:
                    return True
        return False
