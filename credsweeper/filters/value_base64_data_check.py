import base64
import contextlib
import string

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter
from credsweeper.utils import Util


class ValueBase64DataCheck(Filter):
    """
    Check that candidate is NOT an ascii encoded string with entropy check
    """

    def __init__(self, config: Config = None) -> None:
        pass

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received weird base64 token which must be a random string

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, when need to filter candidate and False if left

        """
        if not line_data.value:
            return True
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
            value_len = len(value)
            if 0x3 & value_len:
                # Bitbucket client id is 18 chars length
                pad_len = 4 - (0x3 & value_len)
                value = value + ''.join(['='] * pad_len)
            if '-' in value or '_' in value:
                decoded = base64.urlsafe_b64decode(value)
            else:
                decoded = base64.standard_b64decode(value)
            return Util.is_ascii_entropy_validate(decoded)
        return True
