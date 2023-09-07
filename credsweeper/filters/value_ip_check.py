import contextlib
import ipaddress

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter


class ValueIPCheck(Filter):
    """Filter out some of insensible IP"""

    FALSE_POSITIVE_MARKERS = ["version", "oid", "section", "rfc"]

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
                # use line_strip_lower due the property should be cached already
                line_strip_lower = target.line_strip_lower
                for i in ValueIPCheck.FALSE_POSITIVE_MARKERS:
                    if i in line_strip_lower:
                        return True
            if ip.is_loopback or ip.is_private or ip.is_reserved or ip.is_link_local or ip.is_multicast:
                return True
            return False

        return True
