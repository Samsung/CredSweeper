import contextlib
import string

from credsweeper.common.constants import LATIN_1, ASCII
from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter
from credsweeper.utils import Util


class ValueJWTLiteCheck(Filter):
    """
    Lite check for Json Web Token in base64 encoding.
    Checks first 12 decoded bytes - only ascii symbols allowed.
    It requires only 16 symbols in base64 encoding.
    eyJ0eXAiOm51bGx9 -> {"typ":null}
    """

    def __init__(self, config: Config = None) -> None:
        self.printable = set(string.printable)

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received token which might be structured.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, when need to filter candidate and False if left

        """
        if not line_data.value or 16 > len(line_data.value):
            return True
        with contextlib.suppress(Exception):
            decoded = Util.decode_base64(line_data.value[0:16], urlsafe_detect=True)
            for i in decoded.decode(ASCII):
                # check that only printable symbols must be
                if i not in self.printable:
                    break
            else:
                # no wrong symbols found - may be a JWT
                return False
        return True
