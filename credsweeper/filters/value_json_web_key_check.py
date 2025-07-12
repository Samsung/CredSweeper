import contextlib
from typing import Optional

from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters.filter import Filter
from credsweeper.utils.util import Util


class ValueJsonWebKeyCheck(Filter):
    """
    Check that candidate is JWK which starts usually from 'e'
    and have private parts of the key
    https://datatracker.ietf.org/doc/html/rfc7517
    https://datatracker.ietf.org/doc/html/rfc7518
    """

    def __init__(self, config: Optional[Config] = None) -> None:
        pass

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received key which might be structured.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, when need to filter candidate and False if left

        """
        with contextlib.suppress(Exception):
            if data := Util.decode_base64(line_data.value, padding_safe=True, urlsafe_detect=True):
                if b'"kty":' in data and (b'"oct"' in data and b'"k":' in data or
                                          (b'"EC"' in data or b'"RSA"' in data) and b'"d":' in data):
                    return False
        return True
