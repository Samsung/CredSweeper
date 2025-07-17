import contextlib
import string
from typing import Optional

from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters.filter import Filter
from credsweeper.utils.util import Util


class ValueBase64DataCheck(Filter):
    """
    Check that candidate is NOT an ascii encoded string with entropy check
    """

    def __init__(self, config: Optional[Config] = None) -> None:
        pass

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received weird base64 token which must be a random string

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, when need to filter candidate and False if left

        """
        value = line_data.value
        # check whether digits, lower and upper cases present
        for string_set in [string.digits, string.ascii_lowercase, string.ascii_uppercase]:
            for digit in string_set:
                if digit in value:
                    break
            else:
                return True
        # check whether decoded bytes have enough entropy
        with contextlib.suppress(Exception):
            decoded = Util.decode_base64(value, padding_safe=True, urlsafe_detect=True)
            return Util.is_ascii_entropy_validate(decoded)
        return True
