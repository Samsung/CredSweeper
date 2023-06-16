from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter


class ValueFilePathCheck(Filter):
    r"""Check that candidate value is a path or not.

    Check if a value contains either '/' or ':\' separators (but not both)
    and do not have any special characters ( !$`&*()+)
    """

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
        contains_unix_separator = '/' in line_data.value
        contains_windows_separator = ':\\' in line_data.value
        contains_special_characters = False
        for i in " !$`&*()+":
            if i in line_data.value:
                contains_special_characters = True
                break
        if (contains_unix_separator ^ contains_windows_separator) and not contains_special_characters:
            return True
        return False
