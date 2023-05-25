import base64
import binascii
import contextlib

from credsweeper.common.constants import LATIN_1
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
        with contextlib.suppress(Exception):
            # atlassian integer:bytes from base64
            if line_data.value.startswith("BBDC-"):
                # Bitbucket HTTP Access Token
                return ValueStructuredTokenCheck.check_atlassian_struct(line_data.value[5:])
            if line_data.value.startswith("ATBB"):
                # Bitbucket App password
                return ValueStructuredTokenCheck.check_crc32_struct(line_data.value)
            else:
                # Jira / Confluence PAT token
                return ValueStructuredTokenCheck.check_atlassian_struct(line_data.value)
        return True

    @staticmethod
    def check_crc32_struct(value: str) -> bool:
        """Returns False if value is valid for bitbucket app password structure 'payload:crc32'"""
        crc32 = int(value[28:], 16)
        data = value[:28].encode("ascii")
        if crc32 == binascii.crc32(data):
            return False
        return True

    @staticmethod
    def check_atlassian_struct(value: str) -> bool:
        """Returns False if value is valid for atlassian structure 'integer:bytes'"""
        decoded = base64.b64decode(value)
        delimeter_pos = decoded.find(b':')
        if delimeter_pos > 0:
            val = decoded[:delimeter_pos].decode(LATIN_1)
            if int(val):
                return False
        else:
            val = decoded[:4].decode(LATIN_1)
            if int(val):
                return False
        return True
