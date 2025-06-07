from credsweeper.common import static_keyword_checklist
from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters.filter import Filter


class ValueCoupleKeywordCheck(Filter):
    """Check value if TWO words from morphemes checklist exists in value"""

    def __init__(self, config: Config = None, threshold=1) -> None:
        # threshold - minimum morphemes number in a value
        self.threshold = threshold

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, if need to filter candidate and False if left

        """
        return static_keyword_checklist.check_morphemes(line_data.value.lower(), self.threshold)
