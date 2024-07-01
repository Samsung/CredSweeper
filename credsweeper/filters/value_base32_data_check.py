import base64
import contextlib
import string

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter
from credsweeper.utils import Util


class ValueBase32DataCheck(Filter):
    """
    Check that candidate is NOT an ascii encoded string with entropy check
    """

    def __init__(self, config: Config = None) -> None:
        pass

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received weird base32 token which must be a random string

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, when need to filter candidate and False if left

        """
        value = line_data.value
        # check whether digits and upper cases present
        for string_set in [string.digits, string.ascii_uppercase]:
            for digit in string_set:
                if digit in value:
                    break
            else:
                return True
        # check whether decoded bytes have enough entropy
        with contextlib.suppress(Exception):
            decoded = base64.b32decode(value)
            return Util.is_ascii_entropy_validate(decoded)
        return True
