import contextlib
import ipaddress
import re

from credsweeper.common.constants import ML_HUNK
from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter
from credsweeper.utils import Util


class ValueIPCheck(Filter):
    """Filter out some of insensible IP"""

    TRUE_POSITIVE_MARKERS = [r"\bip\b", "server", "addr", "login"]
    TRUE_POSITIVE_PATTERN = re.compile(Util.get_regex_combine_or(TRUE_POSITIVE_MARKERS), flags=re.IGNORECASE)

    FALSE_POSITIVE_MARKERS = ["version", "oid", "section", "rfc"]
    FALSE_POSITIVE_PATTERN = re.compile(Util.get_regex_combine_or(FALSE_POSITIVE_MARKERS), flags=re.IGNORECASE)

    def __init__(self, config: Config = None) -> None:
        pass

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, if need to filter candidate and False if left

        """
        if not line_data.value:
            return True

        with contextlib.suppress(Exception):
            ip = ipaddress.ip_address(line_data.value)
            if 4 == ip.version:
                byte_sum = sum(x for x in ip.packed)
                if 100 > (byte_sum >> 2):
                    # versions usually have low average of sum the bytes
                    search_text = Util.subtext(line_data.line, line_data.value_start, ML_HUNK)
                    if self.FALSE_POSITIVE_PATTERN.search(search_text) \
                            and not self.TRUE_POSITIVE_PATTERN.search(search_text):
                        return True
            if ip.is_loopback or ip.is_private or ip.is_reserved or ip.is_link_local or ip.is_multicast:
                return True
            return False

        return True
