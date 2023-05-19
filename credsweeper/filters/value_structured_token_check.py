import base64
import contextlib
import json

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
        value_len = len(line_data.value)
        with contextlib.suppress(Exception):
            # atlassian integer:bytes from base64
            if line_data.value.startswith("BBDC-"):
                # Bitbucket HTTP Access Token
                return ValueStructuredTokenCheck.check_atlassian_struct(line_data.value[5:])
            elif line_data.value.startswith("eyJ"):
                # Azure jwt token
                delimiter_pos = line_data.value.find(".")
                if -1 != delimiter_pos:
                    return ValueStructuredTokenCheck.check_jwt_struct(line_data.value[:delimiter_pos])
                else:
                    return ValueStructuredTokenCheck.check_partially_jwt_struct(line_data.value[:value_len -
                                                                                                value_len % 4])
            else:
                # Jira / Confluence PAT token
                return ValueStructuredTokenCheck.check_atlassian_struct(line_data.value)
        return True

    @staticmethod
    def check_jwt_struct(value: str) -> bool:
        """Returns False if decoded value has json structure"""
        decoded = base64.b64decode(value)
        if json.loads(decoded):
            return False
        return True

    @staticmethod
    def check_partially_jwt_struct(value: str) -> bool:
        """Returns False if decoded value has { , : "JWT" substrings"""
        decoded = base64.b64decode(value)
        if b'"JWT"' in decoded and b',' in decoded and b'{' in decoded:
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
