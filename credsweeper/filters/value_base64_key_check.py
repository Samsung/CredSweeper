import contextlib
from typing import Optional

from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters.filter import Filter
from credsweeper.utils.util import Util


class ValueBase64KeyCheck(Filter):
    """Check that candidate contains base64 encoded private key"""

    EXTRA_TRANS_TABLE = str.maketrans('', '', "\",'\\")

    def __init__(self, config: Optional[Config] = None) -> None:
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
            # remove backslash escaping sequences
            text = Util.PEM_CLEANING_PATTERN.sub(r'', line_data.value)
            # remove whitespaces
            text = text.translate(Util.WHITESPACE_TRANS_TABLE)
            # clean sequence concatenation case:
            text = text.replace("'+'", '')
            text = text.replace('"+"', '')
            # possibly url based escaping:
            text = text.replace('%2B', '+')
            text = text.replace('%2F', '/')
            text = text.replace('%3D', '=')
            # clean any other chars which should not appear
            text = text.translate(ValueBase64KeyCheck.EXTRA_TRANS_TABLE)
            # only PEM standard encoding supported in regex pattern to cut off ending of the key
            key = Util.decode_base64(text, padding_safe=True, urlsafe_detect=False)
            private_key = Util.load_pk(key, password=None)
            if Util.check_pk(private_key):
                return False
        return True
