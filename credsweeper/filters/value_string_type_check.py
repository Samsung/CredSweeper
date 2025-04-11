import re

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter


class ValueStringTypeCheck(Filter):
    r"""Check if line_data is in source code file that require quotes for string declaration.

    If it is, then checks if line_data really have string literal declaration.
    Comment rows in source files (start with //, /\*, etc) ignored.
    Multiple bytes scenario allowed [123,23,54,67,78,89] or {0xae, 0x54, 0x55, 0xff}

    True if:

    - line_data have no value
    - line_data have no path
    - line_data is in source code file (.cpp, .py, etc.) and is not comment
      and contain no quotes (so no string literal declared)

    False otherwise
    """

    MULTIBYTE_PATTERN = re.compile(r"(\s*(0x)?[0-9a-f]{1,3}\s*,){8,80}", flags=re.IGNORECASE)

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
        if not self.check_for_literals or line_data.url_part:
            return False

        if ValueStringTypeCheck.MULTIBYTE_PATTERN.match(line_data.value):
            return False

        if line_data.is_source_file_with_quotes() \
                and not line_data.is_comment() \
                and not line_data.is_well_quoted_value \
                and not line_data.is_quoted \
                and line_data.separator and '=' in line_data.separator:
            # heterogeneous code e.g. YAML in Python uses colon sign instead equals
            return True

        return False
