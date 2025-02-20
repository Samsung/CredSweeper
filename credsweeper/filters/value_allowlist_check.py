import re

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter
from credsweeper.utils import Util


class ValueAllowlistCheck(Filter):
    """Check that the patterns do not MATCH the candidate value."""

    ALLOWED = [
        r"ENC\(.*\)",  #
        r"ENC\[.*\]",  #
        r"\$\{(\*|[0-9]+|[a-z_].*)\}",  #
        r"\$[0-9]+(\s|$)",  #
        r"\$\$[a-z_]+(\^%[0-9a-z_]+)?",  #
        r"#\{.*\}",  #
        r"\{\{.+\}\}",  #
        r".*@@@hl@@@(암호|비번|PW|PASS)@@@endhl@@@",  #
    ]

    ALLOWED_PATTERN = re.compile(Util.get_regex_combine_or(ALLOWED), flags=re.IGNORECASE)

    ALLOWED_QUOTED = [
        r"\$[a-z_]+[0-9a-z_]*([$\s]|$)",  #
        r".*\*\*\*",  #
    ]

    ALLOWED_QUOTED_PATTERN = re.compile(Util.get_regex_combine_or(ALLOWED_QUOTED), flags=re.IGNORECASE)

    ALLOWED_UNQUOTED = [
        r"[~a-z0-9_]+((\.|->)[a-z0-9_]+)+\(.*$",  #
        r"\$[a-z_]+[0-9a-z_]*\b",  #
        r".*\*\*\*\*\*",  #
    ]

    ALLOWED_UNQUOTED_PATTERN = re.compile(Util.get_regex_combine_or(ALLOWED_UNQUOTED), flags=re.IGNORECASE)

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
        elif line_data.is_well_quoted_value:
            if self.ALLOWED_QUOTED_PATTERN.match(line_data.value):
                return True
        else:
            if self.ALLOWED_UNQUOTED_PATTERN.match(line_data.value):
                return True

        return False
