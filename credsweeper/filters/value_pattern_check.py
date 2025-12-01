import re
from typing import Optional

from credsweeper.common.constants import DEFAULT_PATTERN_LEN, MAX_LINE_LENGTH, MIN_DATA_LEN
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

    MAX_PATTERN_LENGTH = int(MAX_LINE_LENGTH).bit_length()

    def __init__(self, config: Optional[Config] = None, pattern_len: Optional[int] = None):
        """Create ValuePatternCheck with a specific pattern_len to check.

        Args:
            config: pattern len to use during check. DEFAULT_PATTERN_LEN by default
            pattern_len: size of constant pattern length for any value size or None for dynamic pattern size

        """
        patterns_count = 1 + ValuePatternCheck.MAX_PATTERN_LENGTH
        if pattern_len is None:
            self.pattern_len = -1
            # pattern length depends on value length
            self.pattern_lengths = [max(x, DEFAULT_PATTERN_LEN) for x in range(patterns_count)]
            self.patterns = [ValuePatternCheck.get_pattern(x) for x in range(patterns_count)]
        elif isinstance(pattern_len, int) and DEFAULT_PATTERN_LEN <= pattern_len:
            self.pattern_len = pattern_len
            # constant pattern for any value length
            self.pattern_lengths = [pattern_len] * patterns_count
            self.patterns = [ValuePatternCheck.get_pattern(pattern_len)] * patterns_count
        else:
            raise ValueError(f"Wrong type of pattern length {type(pattern_len)} = {repr(pattern_len)}")

    @staticmethod
    def get_pattern(pattern_len: int) -> re.Pattern:
        """Creates regex pattern to find N or more identical characters in sequence"""
        pattern_length = max(DEFAULT_PATTERN_LEN, pattern_len)
        if MIN_DATA_LEN <= pattern_length:
            # base64 long sequences may contain 0x00 or 0xFF inside
            pattern = fr"([^\sA/_])\1{{{str(pattern_length-1)},}}"
        else:
            # up to 256 symbols length
            pattern = fr"(\S)\1{{{str(pattern_length-1)},}}"
        return re.compile(pattern)

    def equal_pattern_check(self, value: str, bit_length: int) -> bool:
        """Check if candidate value contain 4 and more same chars or numbers sequences.

        Args:
            value: string variable, credential candidate value
            bit_length: speedup for len(value).bit_length()

        Return:
            True if contain and False if not

        """
        if self.patterns[bit_length].search(value):
            return True
        return False

    def ascending_pattern_check(self, value: str, bit_length: int) -> bool:
        """Check if candidate value contain 4 and more ascending chars or numbers sequences.

        Arg:
            value: credential candidate value
            bit_length: speedup for len(value).bit_length()

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
            if count == self.pattern_lengths[bit_length]:
                return True
        return False

    def descending_pattern_check(self, value: str, bit_length: int) -> bool:
        """Check if candidate value contain 4 and more descending chars or numbers sequences.

        Arg:
            value: string variable, credential candidate value
            bit_length: speedup for len(value).bit_length()

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
            if count == self.pattern_lengths[bit_length]:
                return True
        return False

    def check_val(self, value: str, bit_length: int) -> bool:
        """Cumulative value check.

        Arg:
            value: string variable, credential candidate value
            bit_length: speedup for len(value).bit_length()

        Return:
            boolean variable. True if contain and False if not

        """
        if self.equal_pattern_check(value, bit_length):
            return True
        if self.ascending_pattern_check(value, bit_length):
            return True
        if self.descending_pattern_check(value, bit_length):
            return True
        return False

    def duple_pattern_check(self, value: str, bit_length: int) -> bool:
        """Check if candidate value is a duplet value with possible patterns.

        Arg:
            value: string variable, credential candidate value
            bit_length: speedup for len(value).bit_length()

        Return:
            boolean variable. True if contain and False if not

        """
        even_value = value[0::2]
        if self.check_val(even_value, bit_length):
            odd_value = value[1::2]
            if self.check_val(odd_value, bit_length):
                return True
        return False

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Arg:
            line_data: LineData object, credential candidate data
            target: multiline target from which line data was obtained

        Return:
            boolean variable. True, if need to filter candidate and False if left

        """
        value_length = len(line_data.value)
        bit_length = max(DEFAULT_PATTERN_LEN, value_length.bit_length())

        if ValuePatternCheck.MAX_PATTERN_LENGTH < bit_length:
            # huge values may contain anything
            return False

        if 0 <= value_length < self.pattern_len or value_length < self.pattern_lengths[bit_length]:
            # too short value
            return True

        if self.check_val(line_data.value, bit_length):
            return True

        if 2 * self.pattern_lengths[bit_length] <= value_length \
                and self.duple_pattern_check(line_data.value, bit_length):
            return True

        return False
