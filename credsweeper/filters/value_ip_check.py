import contextlib
import ipaddress
import re

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter
from credsweeper.utils import Util


class ValueIPCheck(Filter):
    """Filter out some of insensible IP"""

    FALSE_POSITIVE_MARKERS = ["version", "oid", "section", "rfc"]
    FALSE_POSITIVE_PATTERN = re.compile(Util.get_regex_combine_or(FALSE_POSITIVE_MARKERS))

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
                if self.FALSE_POSITIVE_PATTERN.search(target.line_lower, line_data.search_start, line_data.search_end):
                    return True
            if ip.is_loopback or ip.is_private or ip.is_reserved or ip.is_link_local or ip.is_multicast:
                return True
            return False

        return True
