import re

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter


class ValueLastWordCheck(Filter):
    """Check that secret is not short value that ends with `:`."""

    NOT_ALLOWED_COLON_PATTERN = re.compile(".*:$", flags=re.IGNORECASE)

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
        if len(line_data.value) < 16 and self.NOT_ALLOWED_COLON_PATTERN.search(line_data.value):
            return True
        return False
