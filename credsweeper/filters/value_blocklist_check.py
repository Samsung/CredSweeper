from typing import Optional

from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters.filter import Filter


class ValueBlocklistCheck(Filter):
    """Check that words from block list is lest that 70% of candidate value length."""

    NOT_ALLOWED = [
        "true",
        "false",
        "null",
        "none",
        "bearer",
        "string",
        "value",
        "undefined",
    ]

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

        value = line_data.value.lower()
        for not_allowed in self.NOT_ALLOWED:
            if not_allowed in value and len(not_allowed) / len(value) >= 0.7:
                return True

        return False
