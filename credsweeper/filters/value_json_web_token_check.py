import base64
import contextlib
import json

from credsweeper.credentials import LineData
from credsweeper.filters import Filter


class ValueJsonWebTokenCheck(Filter):
    """
    Check that candidate is JWT which starts usually from 'eyJ'
    only header is parsed with "typ" or "alg" member from example of RFC7519
    https://datatracker.ietf.org/doc/html/rfc7519
    """

    def run(self, line_data: LineData) -> bool:
        """Run filter checks on received token which might be structured.

        Args:
            line_data: credential candidate data

        Return:
            True, when need to filter candidate and False if left

        """
        if not line_data.value:
            return True
        with contextlib.suppress(Exception):
            delimiter_pos = line_data.value.find(".")
            # jwt token. '.' must be always in given data, according regex in rule
            value = line_data.value[:delimiter_pos]
            decoded = base64.b64decode(value)
            if header := json.loads(decoded):
                if "alg" in header or "typ" in header:
                    return False
        return True
