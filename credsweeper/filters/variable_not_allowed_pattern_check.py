import re

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter
from credsweeper.utils import Util


class VariableNotAllowedPatternCheck(Filter):
    """Check if candidate variable is a regex placeholder or ends with match character (like + or >)."""

    NOT_ALLOWED = ["^([<]|\\{\\{).*", "(\\@.*)", "[!><+*/^|)](\\s)?$", ".*(public|pubkey)"]
    NOT_ALLOWED_PATTERN = re.compile(  #
        Util.get_regex_combine_or(NOT_ALLOWED),  #
        flags=re.IGNORECASE)

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
        if line_data.variable is None:
            return True

        if self.NOT_ALLOWED_PATTERN.match(line_data.variable):
            return True

        return False
