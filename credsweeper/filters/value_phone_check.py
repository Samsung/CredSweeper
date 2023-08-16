import contextlib
import re

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter


class ValuePhoneCheck(Filter):
    """Check that value may be a phone number"""

    def __init__(self, config: Config = None) -> None:
        pass

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            False, if the sequence is not card number. True if it is

        """
        if line_data.value is None:
            return True

        if line_data.value.startswith('+'):
            value = line_data.value
            value.translate("+- )(")
            with contextlib.suppress(Exception):
                num = int(value)
                return False
        else:
            if re.compile(r"[1-9][0-9]{2}-[0-9]{3}-[0-9]{4}").search(line_data.value):
                return False


        return True
