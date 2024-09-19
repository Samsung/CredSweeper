from credsweeper.common.constants import Chars
from credsweeper.common import static_keyword_checklist
from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter, ValueEntropyBase64Check
from credsweeper.utils import Util


class ValueFilePathCheck(Filter):
    """Check that candidate value is a path or not.

    Check if a value contains either '/' or ':\' separators (but not both)
    and do not have any special characters ( !$@`&*()+)
    """
    base64_possible_set = set(Chars.BASE64_CHARS.value) | set(Chars.BASE64URL_CHARS.value)
    unusual_windows_symbols_in_path = "\t\n\r !$@`&*()[]{}<>+=;,~^"
    unusual_linux_symbols_in_path = unusual_windows_symbols_in_path + ":\\"

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
        value = line_data.value
        contains_unix_separator = '/' in value
        if contains_unix_separator:
            if ("://" in value  #
                    or value.startswith("~/")  #
                    or value.startswith("./")  #
                    or "../" in value  #
                    or "/.." in value  #
                    or value.startswith("//") and ':' == line_data.separator):
                # common case for url definition or aliases
                # or _keyword_://example.com where : is the separator
                return static_keyword_checklist.check_morphemes(value.lower(), 1)
            # base64 encoded data might look like linux path
            min_entropy = ValueEntropyBase64Check.get_min_data_entropy(len(value))
            # get minimal entropy to compare with shannon entropy of found value
            # min_entropy == 0 means that the value cannot be checked with the entropy due high variance
            for i in value:
                if i not in self.base64_possible_set:
                    # value contains wrong BASE64STD_CHARS symbols like .
                    break
            else:
                # all symbols are from base64 alphabet
                entropy = Util.get_shannon_entropy(value, Chars.BASE64STD_CHARS.value)
                if 0 == min_entropy or min_entropy > entropy:
                    contains_unix_separator = 1 < value.count('/')
                else:
                    # high entropy means base64 encoded data
                    contains_unix_separator = False

            # low shannon entropy points that the value maybe not a high randomized value in base64
        contains_windows_separator = ':\\' in value
        if contains_unix_separator or contains_windows_separator:
            unusual_symbols_in_path = self.unusual_linux_symbols_in_path if contains_unix_separator \
                else self.unusual_windows_symbols_in_path
            for i in unusual_symbols_in_path:
                if i in value:
                    # the symbols which not passed in a path usually
                    break
            else:
                if contains_unix_separator ^ contains_windows_separator:
                    return static_keyword_checklist.check_morphemes(value.lower(), 1)
        return False
