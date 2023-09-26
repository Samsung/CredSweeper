from typing import Union

from credsweeper.common import static_keyword_checklist
from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter


class ValueSplitKeywordCheck(Filter):
    """Check value by splitting with standard whitespace separators and any word is not matched in checklist."""

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
        words: Union[set, list] = line_data.value.lower().split()
        keyword_set = static_keyword_checklist.keyword_set
        for word in words:
            if word in keyword_set:
                return True
        return False
