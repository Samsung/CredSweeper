import contextlib
from typing import Optional

from credsweeper.common.constants import ASCII, PEM_BEGIN_PATTERN
from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters.filter import Filter
from credsweeper.utils.pem_key_detector import PemKeyDetector
from credsweeper.utils.util import Util


class ValueBase64EncodedPem(Filter):
    """Check that candidate contains base64 encoded pem private key"""

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
            text = Util.decode_base64(line_data.value, padding_safe=True, urlsafe_detect=True)
            lines = text.decode(ASCII).splitlines()
            lines_pos = list(range(len(lines)))
            for line_pos, line in zip(lines_pos, lines):
                if PEM_BEGIN_PATTERN in line:
                    new_target = AnalysisTarget(line_pos, lines, lines_pos, target.descriptor)
                    if PemKeyDetector.detect_pem_key(self.config, new_target):
                        # obtained candidates are not used because not match text
                        return False
        return True
