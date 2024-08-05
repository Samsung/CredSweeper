import contextlib
import statistics

from credsweeper.common.constants import Chars
from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter
from credsweeper.utils import Util


class ValueBase64PartCheck(Filter):
    """
    Check that candidate is NOT a part of base64 long line
    """

    def __init__(self, config: Config = None) -> None:
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
            if line_data.value_start and '/' == line_data.line[line_data.value_start - 1]:
                if '-' in line_data.value or '_' in line_data.value:
                    # the value contains url-safe chars, so '/' is a delimiter
                    return False
                value_entropy = Util.get_shannon_entropy(line_data.value, Chars.BASE64STD_CHARS.value)
                left_start = line_data.value_start - len(line_data.value)
                if 0 > left_start:
                    left_start = 0
                left_entropy = Util.get_shannon_entropy(line_data.line[left_start:line_data.value_start],
                                                        Chars.BASE64STD_CHARS.value)
                right_end = line_data.value_end + len(line_data.value)
                if len(line_data.line) < right_end:
                    right_end = len(line_data.line)
                right_entropy = Util.get_shannon_entropy(line_data.line[line_data.value_end:right_end],
                                                         Chars.BASE64STD_CHARS.value)
                data = [value_entropy, left_entropy, right_entropy]
                avg = statistics.mean(data)
                stdev = statistics.stdev(data, avg)
                avg_min = avg - stdev
                if avg_min < left_entropy and avg_min < right_entropy:
                    # high entropy of bound parts looks like a part of base64 long line
                    return True

        return False
