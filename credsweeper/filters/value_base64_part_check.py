import contextlib
import re
import statistics
from itertools import takewhile
from typing import Optional

from credsweeper.common.constants import Chars
from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters.filter import Filter
from credsweeper.filters.value_entropy_base64_check import ValueEntropyBase64Check
from credsweeper.utils.util import Util


class ValueBase64PartCheck(Filter):
    """
    Check that candidate is NOT a part of base64 long line
    """

    base64_pattern = re.compile(r"^(\\{1,8}[0abfnrtv]|[0-9A-Za-z+/=]){1,4000}$")
    base64_char_set = set(Chars.BASE64STDPAD_CHARS.value + '\\')

    def __init__(self, config: Optional[Config] = None) -> None:
        pass

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received weird base64 token which must be a random string

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, when need to filter candidate and False if left

        """

        with contextlib.suppress(Exception):
            line = line_data.line
            len_line = len(line)
            value = line_data.value
            len_value = len(value)
            if 0 == line_data.value_start and len_line >= 2 * len_value \
                    or 0 < line_data.value_start and line[line_data.value_start - 1] in ('/', '+', '\\', '%') \
                    or 0 < line_data.value_end < len_line and line[line_data.value_end] in ('/', '+', '\\', '%'):

                if '-' in value or '_' in value:
                    # the value contains url-safe chars, so '/' or '+' is a delimiter
                    return False

                left_start = line_data.value_start - len_value
                if 0 > left_start:
                    left_start = 0
                right_end = line_data.value_end + len_value
                if len_line < right_end:
                    right_end = len_line

                hunk_size = right_end - left_start

                if hunk_size == 3 * len_value:
                    # simple analysis for maximal data size
                    if self.base64_pattern.match(line[left_start:right_end]):
                        # obvious case: all characters are base64 standard
                        return True
                elif right_end - left_start >= 2 * len_value:
                    # simple analysis for data too large to yield sensible insights
                    part_set = set(line[left_start:right_end])
                    if not part_set.difference(ValueBase64PartCheck.base64_char_set):
                        # obvious case: all characters are base64 standard
                        return True

                left_part = ''.join(
                    takewhile(lambda x: x in ValueBase64PartCheck.base64_char_set,
                              reversed(line[left_start:line_data.value_start])))

                right_part = ''.join(
                    takewhile(lambda x: x in ValueBase64PartCheck.base64_char_set, line[line_data.value_end:right_end]))

                min_entropy_value = ValueEntropyBase64Check.get_min_data_entropy(len_value)

                left_entropy = Util.get_shannon_entropy(left_part)
                value_entropy = Util.get_shannon_entropy(value)
                right_entropy = Util.get_shannon_entropy(right_part)
                common = left_part + value + right_part
                common_entropy = Util.get_shannon_entropy(common)
                min_entropy_common = ValueEntropyBase64Check.get_min_data_entropy(len(common))
                if min_entropy_common < common_entropy:
                    return True

                if left_entropy and right_entropy:
                    data = [left_entropy, value_entropy, right_entropy, min_entropy_value, common_entropy]
                elif left_entropy and not right_entropy:
                    data = [left_entropy, value_entropy, min_entropy_value, min_entropy_value, common_entropy]
                elif not left_entropy and right_entropy:
                    data = [value_entropy, right_entropy, min_entropy_value, min_entropy_value, common_entropy]
                else:
                    return False

                avg = statistics.mean(data)
                stdev = statistics.stdev(data, avg)
                avg_min = avg - 1.1 * stdev
                if (0. == left_entropy or avg_min < left_entropy or left_entropy < value_entropy < right_entropy) \
                        and (
                        0. == right_entropy or avg_min < right_entropy or right_entropy < value_entropy < left_entropy):
                    # high entropy of bound parts looks like a part of base64 long line
                    return True
                else:
                    return False

        return False
