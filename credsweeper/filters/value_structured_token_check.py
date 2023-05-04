import base64

from credsweeper.credentials import LineData
from credsweeper.filters import Filter


class ValueStructuredTokenCheck(Filter):
    """Check that candidate have a known structure"""

    def run(self, line_data: LineData) -> bool:
        """Run filter checks on received token which might be structured.

        Args:
            line_data: credential candidate data

        Return:
            True, if need to filter candidate and False if left

        """
        if not line_data.value:
            return True
        # atlassian integer:bytes from base64
        try:
            decoded = base64.b64decode(line_data.value)
            delimeter_pos = decoded.find(b':')
            val = decoded[:delimeter_pos].decode('latin_1')
            if int(val):
                return False
        except Exception:
            pass
        return True
