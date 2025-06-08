import re

from credsweeper.common.constants import DEFAULT_PATTERN_LEN
from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters.filter import Filter


class ValuePatternCheck(Filter):
    """Check if candidate value contain specific pattern.

    Similar to linguistic sequences of characters, random strings shouldn't contain math sequences of
    characters. Based on "How Bad Can It Git? Characterizing Secret Leakage in Public GitHub Repositories", details:
    https://www.ndss-symposium.org/ndss-paper/how-bad-can-it-git-characterizing-secret-leakage-in-public-github-repositories/
    PatternCheck checks the occurrence in "line_data.value" of three types of sequence:

    - N or more identical characters in sequence, example: "AAAA", "1111" ...
    - N or more increasing characters sequentially, example: "abcd", "1234" ...
    - N or more decreasing characters sequentially, example: "dcba", "4321" ...

    Default pattern LEN is 4
    """

    def __init__(self, config: Config = None, pattern_len: int = DEFAULT_PATTERN_LEN):
        """Create ValuePatternCheck with a specific pattern_len to check.

        Args:
            config: pattern len to use during check. DEFAULT_PATTERN_LEN by default

        """
        self.pattern_len = pattern_len
        # use non whitespace symbol pattern
        self.pattern = re.compile(fr"(\S)\1{{{str(self.pattern_len - 1)},}}")

    def equal_pattern_check(self, value: str) -> bool:
        """Check if candidate value contain 4 and more same chars or numbers sequences.

        Args:
            value: string variable, credential candidate value

        Return:
            True if contain and False if not

        """
        if self.pattern.findall(value):
            return True
        return False

    def ascending_pattern_check(self, value: str) -> bool:
        """Check if candidate value contain 4 and more ascending chars or numbers sequences.

        Arg:
            value: credential candidate value

        Return:
            True if contain and False if not

        """
        count = 1
        for key in range(len(value) - 1):
            if ord(value[key + 1]) - ord(value[key]) == 1:
                count += 1
            else:
                count = 1
                continue
            if count == self.pattern_len:
                return True
        return False

    def descending_pattern_check(self, value: str) -> bool:
        """Check if candidate value contain 4 and more descending chars or numbers sequences.

        Arg:
            value: string variable, credential candidate value

        Return:
            boolean variable. True if contain and False if not

        """
        count = 1
        for key in range(len(value) - 1):
            if ord(value[key]) - ord(value[key + 1]) == 1:
                count += 1
            else:
                count = 1
                continue
            if count == self.pattern_len:
                return True
        return False

    def check_val(self, value: str) -> bool:
        """Cumulative value check.

        Arg:
            value: string variable, credential candidate value

        Return:
            boolean variable. True if contain and False if not

        """
        if self.equal_pattern_check(value):
            return True
        if self.ascending_pattern_check(value):
            return True
        if self.descending_pattern_check(value):
            return True
        return False

    def duple_pattern_check(self, value: str) -> bool:
        """Check if candidate value is a duplet value with possible patterns.

        Arg:
            value: string variable, credential candidate value

        Return:
            boolean variable. True if contain and False if not

        """
        # 001122334455... case
        pair_duple = True
        # 0102030405... case
        even_duple = True
        even_prev = value[0]
        even_value = value[0::2]
        # 1020304050... case
        odd_duple = True
        odd_prev = value[1]
        odd_value = value[1::2]
        for even_i, odd_i in zip(even_value, odd_value):
            pair_duple &= even_i == odd_i
            even_duple &= even_i == even_prev
            odd_duple &= odd_i == odd_prev
            if not pair_duple and not even_duple and not odd_duple:
                break
        else:
            if pair_duple or odd_duple:
                return self.check_val(even_value)
            if even_duple:
                return self.check_val(odd_value)
        return False

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Arg:
            line_data: LineData object, credential candidate data
            target: multiline target from which line data was obtained

        Return:
            boolean variable. True, if need to filter candidate and False if left

        """
        if len(line_data.value) < self.pattern_len:
            return True

        if self.check_val(line_data.value):
            return True

        if 2 * self.pattern_len <= len(line_data.value) and self.duple_pattern_check(line_data.value):
            return True

        return False
