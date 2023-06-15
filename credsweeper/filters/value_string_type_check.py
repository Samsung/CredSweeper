from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter


class ValueStringTypeCheck(Filter):
    r"""Check if line_data is in source code file that require quotes for string declaration.

    If it is, then checks if line_data really have string literal declaration.
    Comment rows in source files (start with //, /\*, etc) ignored.

    True if:

    - line_data have no value
    - line_data have no path
    - line_data is in source code file (.cpp, .py, etc.) and is not comment
      and contain no quotes (so no string literal declared)

    False otherwise
    """

    def __init__(self, config: Config) -> None:
        self.check_for_literals = config.check_for_literals

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, if need to filter candidate and False if left

        """
        if not self.check_for_literals:
            return False

        if not line_data.value:
            return True

        if line_data.path is None:
            return True

        not_quoted = not line_data.value_leftquote and not line_data.value_rightquote
        not_comment = not line_data.is_comment()

        if line_data.is_source_file_with_quotes() and not_comment and not_quoted:
            return True

        return False
