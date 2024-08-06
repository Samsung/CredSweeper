import contextlib
import json

from credsweeper.common.constants import Chars
from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter
from credsweeper.filters.value_entropy_base64_check import ValueEntropyBase64Check
from credsweeper.utils import Util


class ValueAzureTokenCheck(Filter):
    """
    Azure tokens contains header, payload and signature
    https://learn.microsoft.com/en-us/azure/active-directory-b2c/access-tokens
    """

    def __init__(self, config: Config = None) -> None:
        pass

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received token which might be structured.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, when need to filter candidate and False if left

        """
        with contextlib.suppress(Exception):
            parts = line_data.value.split('.')
            if 3 != len(parts):
                return True
            hdr = Util.decode_base64(parts[0], padding_safe=True, urlsafe_detect=True)
            header = json.loads(hdr)
            if not ("alg" in header and "typ" in header and "kid" in header):
                # must be all parts in header
                return True
            pld = Util.decode_base64(parts[1], padding_safe=True, urlsafe_detect=True)
            payload = json.loads(pld)
            if not ("iss" in payload and "exp" in payload and "iat" in payload):
                # must be all parts in payload
                return True
            min_entropy = ValueEntropyBase64Check.get_min_data_entropy(len(parts[2]))
            entropy = Util.get_shannon_entropy(parts[2], Chars.BASE64URL_CHARS.value)
            # good signature has to be like random bytes
            return entropy < min_entropy

        return True
