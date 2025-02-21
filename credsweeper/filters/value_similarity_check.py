from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter


class ValueSimilarityCheck(Filter):
    """Check if candidate value is at least 70% same as candidate keyword. Like: `secret = "mysecret"`."""

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
        # Cannot evaluate if key is None
        if line_data.key is None:
            return False
        if line_data.key.lower() in line_data.value.lower() and \
                len(line_data.key) / len(line_data.value) >= 0.7:
            return True
        if line_data.variable is not None and line_data.value in line_data.variable:
            return True
        return False
