import contextlib
import string

from cryptography.hazmat.primitives import serialization

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter
from credsweeper.utils import Util


class ValueBase64KeyCheck(Filter):
    """Check that candidate contains base64 encoded private key"""

    def __init__(self, config: Config = None) -> None:
        self.config = config

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received token which might be structured.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, if need to filter candidate and False if left

        """

        with contextlib.suppress(Exception):
            text = line_data.value
            # replace to space any escaped sequence except space from string.whitespace
            for x in ["\\t", "\\n", "\\r", "\\v", "\\f"]:
                text = text.replace(x, ' ')
            for x in string.whitespace:
                text = text.replace(x, '')
            # clean sequence concatenation case:
            text = text.replace("'+'", '')
            text = text.replace('"+"', '')
            # possibly url based escaping:
            text = text.replace('%2B', '+')
            text = text.replace('%2F', '/')
            text = text.replace('%3D', '=')
            # clean any other chars which should not appear
            for x in ["'", '"', '\\', ',']:
                text = text.replace(x, "")
            # only PEM standard encoding supported in regex pattern to cut off ending of the key
            key = Util.decode_base64(text, padding_safe=True, urlsafe_detect=False)
            private_key = serialization.load_der_private_key(key, password=None)
            if 0 < private_key.key_size:  # type: ignore
                # access to size field check - some types have no size
                return False
        return True
