from credsweeper.common import static_keyword_checklist
from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter


class ValueDictionaryKeywordCheck(Filter):
    """Check that no word from dictionary present in the candidate value."""

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
        if not line_data.value:
            return True
        line_data_value_lower = line_data.value.lower()
        for keyword in static_keyword_checklist.keyword_set:
            if keyword in line_data_value_lower:
                return True
        return False
