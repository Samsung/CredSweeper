import contextlib
from typing import Optional

from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import ValueAtlassianTokenCheck


class ValueCloudFlareCheck(ValueAtlassianTokenCheck):
    """Check that candidate have a known structure"""

    def __init__(self, config: Optional[Config] = None) -> None:
        super().__init__(config)

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received token with CRC32

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, if need to filter candidate and False if left

        """
        value = line_data.value
        with contextlib.suppress(Exception):
            # atlassian integer:bytes from base64
            if value.startswith("cfk_"):
                # CloudFlare
                return ValueAtlassianTokenCheck.check_crc32_struct(value[4:])
            if value.startswith(("cfat_", "cfut_")):
                # Bitbucket HTTP Access Token & CloudFlare
                return ValueAtlassianTokenCheck.check_crc32_struct(value[5:])
        return True
