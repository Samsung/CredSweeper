import base64
import binascii
import contextlib

from credsweeper.common.constants import LATIN_1
from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter
from credsweeper.utils import Util


class ValueStructuredTokenCheck(Filter):
    """Check that candidate have a known structure"""

    def __init__(self, config: Config = None) -> None:
        pass

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received token which might be structured.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, if need to filter candidate and False if left

        """
        if not line_data.value:
            return True
        value = line_data.value
        with contextlib.suppress(Exception):
            # atlassian integer:bytes from base64
            if value.startswith("BBDC-"):
                # Bitbucket HTTP Access Token
                return ValueStructuredTokenCheck.check_atlassian_struct(value[5:])
            elif value.startswith("ATBB"):
                # Bitbucket App password
                return ValueStructuredTokenCheck.check_crc32_struct(value)
            else:
                # Jira / Confluence PAT token
                return ValueStructuredTokenCheck.check_atlassian_struct(value)
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
        delimiter_pos = decoded.find(b':')
        # there is limit for big integer value: math.log10(1<<64) = 19.265919722494797
        if 0 < delimiter_pos <= 20:
            val = decoded[:delimiter_pos].decode(LATIN_1)
            if int(val):
                # test for ascii and Shannon entropy - there should be random data
                data = decoded[delimiter_pos + 1:]
                return Util.is_ascii_entropy_validate(data)
        return True
