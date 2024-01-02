import re
from typing import Optional

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter


class ValueNotPartEncodedCheck(Filter):
    """Check that token is not a part of encoded data."""

    BASE64_ENCODED_DATA_PATTERN_BEFORE = re.compile(
        r"(^|[^A-Za-z0-9]+)(?P<val>(([A-Za-z0-9_-]{4}){16,64})|(([A-Za-z0-9+/]{4}){16,64}))([^=A-Za-z0-9]+|$)")
    BASE64_ENCODED_DATA_PATTERN_AFTER = re.compile(
        r"(^|[^A-Za-z0-9]+)(?P<val>(([A-Za-z0-9=_-]{4}){4,64})|(([A-Za-z0-9=+/]{4}){4,64}))([^=A-Za-z0-9]+|$)")

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

        if line_data.line_num == target.line_num \
                and len(line_data.line) == target.line_len \
                and line_data.line == target.line \
                and 0 < target.line_num <= target.lines_len \
                and line_data.line == target.lines[target.line_num - 1]:
            # suppose, there is plain lines order
            if 1 < target.line_num:
                result = ValueNotPartEncodedCheck._check_val(
                    target.lines[line_data.line_num - 2], ValueNotPartEncodedCheck.BASE64_ENCODED_DATA_PATTERN_BEFORE)
                if result is not None:
                    return result
            if target.lines_len > target.line_num:
                result = ValueNotPartEncodedCheck._check_val(target.lines[line_data.line_num],
                                                             ValueNotPartEncodedCheck.BASE64_ENCODED_DATA_PATTERN_AFTER)
                if result is not None:
                    return result
        else:
            # otherwise - need to iterate for all lines
            for i in range(target.lines_len):
                if line_data.line == target.lines[i]:
                    if 0 < i:
                        result = ValueNotPartEncodedCheck._check_val(
                            target.lines[i - 1], ValueNotPartEncodedCheck.BASE64_ENCODED_DATA_PATTERN_BEFORE)
                        if result is not None:
                            return result
                    i += 1
                    if target.lines_len > i:
                        result = ValueNotPartEncodedCheck._check_val(
                            target.lines[i], ValueNotPartEncodedCheck.BASE64_ENCODED_DATA_PATTERN_AFTER)
                        if result is not None:
                            return result
                    break
        return False

    @staticmethod
    def _check_val(line: str, pattern: re.Pattern) -> Optional[bool]:
        match_obj = pattern.match(line)
        if match_obj:
            val = match_obj.group("val")
            # not a path-like
            if not val.startswith('/'):
                return True
            # padding sign
            if '=' == val[-1]:
                return True
        return None
