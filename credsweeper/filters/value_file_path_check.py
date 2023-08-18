from credsweeper.common.constants import Chars
from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter, ValueEntropyBase64Check
from credsweeper.utils import Util


class ValueFilePathCheck(Filter):
    r"""Check that candidate value is a path or not.

    Check if a value contains either '/' or ':\' separators (but not both)
    and do not have any special characters ( !$@`&*()+)
    """

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
        value = line_data.value
        contains_unix_separator = '/' in value and not value.endswith('=')
        if contains_unix_separator:
            # base64 encoded data might look like linux path
            min_entropy = ValueEntropyBase64Check.get_min_data_entropy(len(value))
            # get minimal entropy to compare with shannon entropy of found value
            # min_entropy == 0 means that the value cannot be checked with the entropy due high variance
            contains_unix_separator = (0 == min_entropy
                                       or min_entropy > Util.get_shannon_entropy(value, Chars.BASE64STD_CHARS.value))
            # low shannon entropy points that the value maybe not a high randomized value in base64
        contains_windows_separator = ':\\' in value
        for i in " !$@`&*()+":
            if i in value:
                break
        else:
            if contains_unix_separator ^ contains_windows_separator:
                return True
        return False
