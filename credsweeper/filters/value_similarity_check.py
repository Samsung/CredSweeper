from difflib import SequenceMatcher
from typing import Optional

from credsweeper.common.constants import MIN_VALUE_LENGTH
from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters.filter import Filter


class ValueSimilarityCheck(Filter):
    """Check if candidate value is over 75% similarity as candidate variable. Like: `secret = "mysecret"` (0.8571)."""

    def __init__(self, config: Optional[Config] = None) -> None:
        pass

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, if need to filter candidate and False if left

        """
        if line_data.variable and line_data.value:
            variable_lower = line_data.variable.lower()
            value_lower = line_data.value.lower()
            if len(value_lower) <= len(variable_lower):
                if value_lower in variable_lower:
                    return True
            elif MIN_VALUE_LENGTH <= len(variable_lower):
                # `api` and `key` may be in the value
                if variable_lower in value_lower:
                    return True
            if 0.75 < SequenceMatcher(None, variable_lower, value_lower).ratio():
                return True
        return False
