import re

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter
from credsweeper.utils import Util


class ValueAllowlistCheck(Filter):
    """Check that patterns from the list is not present in the candidate value."""

    ALLOWED = [
        r"ENC\(.*\)",  #
        r"ENC\[.*\]",  #
        r"\$\{(\*|[0-9]+|[a-z_].*)\}",  #
        r"\$([0-9]+\b|[a-z_]+[0-9a-z_]*)",  #
        r"\$\$[a-z_]+(\^%[0-9a-z_]+)?",  #
        r"#\{.*\}",  #
        r"\{\{.+\}\}",  #
        r"\S{0,5}\*{5,}",  #
        r".*@@@hl@@@(암호|비번|PW|PASS)@@@endhl@@@",  #
    ]

    ALLOWED_PATTERN = re.compile(Util.get_regex_combine_or(ALLOWED), flags=re.IGNORECASE)
    ALLOWED_UNQUOTED_PATTERN = re.compile(r"[~a-z0-9_]+((\.|->)[a-z0-9_]+)+\(.*$", flags=re.IGNORECASE)

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

        if self.ALLOWED_PATTERN.match(line_data.value):
            return True

        if not line_data.is_well_quoted_value and self.ALLOWED_UNQUOTED_PATTERN.match(line_data.value):
            return True

        return False
