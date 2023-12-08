import contextlib
import re

from credsweeper.common.constants import ASCII
from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter
from credsweeper.utils import Util


class ValueJfrogTokenCheck(Filter):
    """Check that candidate have a known structure JFROG token"""

    def __init__(self, config: Config = None) -> None:
        # reftkn:01:0123456789:abcdefGhijklmnoPqrstuVwxyz0
        self._pattern = re.compile(r"reftkn:\d+:\d+:[\w_/+-]+")
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
        with contextlib.suppress(Exception):
            decoded = Util.decode_base64(line_data.value, padding_safe=True, urlsafe_detect=True)
            if self._pattern.match(decoded.decode(ASCII)):
                return False
        return True
