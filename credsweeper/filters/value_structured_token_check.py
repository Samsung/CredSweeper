import base64

from credsweeper.credentials import LineData
from credsweeper.file_handler.data_content_provider import MIN_ENCODED_DATA_LEN
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
        if not line_data.value or MIN_ENCODED_DATA_LEN > len(line_data.value):
            return True
        try:
            # atlassian integer:bytes from base64
            if "BBDC-" == line_data.value[0:5]:
                # Bitbucket HTTP Access Token
                value = line_data.value[5:]
            else:
                # Jira / Confluence PAT token
                value = line_data.value
            decoded = base64.b64decode(value)
            delimeter_pos = decoded.find(b':')
            val = decoded[:delimeter_pos].decode('latin_1')
            if int(val):
                return False
        except Exception:
            pass
        return True
