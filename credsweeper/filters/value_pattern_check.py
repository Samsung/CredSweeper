import re

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter


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

    def __init__(self, config: Config):
        """Create ValuePatternCheck with a specific pattern_len to check.

        Args:
            config: pattern len to use during check. DEFAULT_PATTERN_LEN by default

        """
        if 'ValuePemPatternCheck' == self.__class__.__name__:
            self.pattern_len = config.pem_pattern_len
        else:
            self.pattern_len = config.pattern_len
        # use non whitespace symbol pattern
        self.pattern = re.compile(fr"(\S)\1{{{str(self.pattern_len - 1)},}}")

    def equal_pattern_check(self, line_data_value: str) -> bool:
        """Check if candidate value contain 4 and more same chars or numbers sequences.

        Args:
            line_data_value: string variable, credential candidate value

        Return:
            True if contain and False if not

        """
        if self.pattern.findall(line_data_value):
            return True
        return False

    def ascending_pattern_check(self, line_data_value: str) -> bool:
        """Check if candidate value contain 4 and more ascending chars or numbers sequences.

        Arg:
            line_data_value: credential candidate value

        Return:
            True if contain and False if not

        """
        count = 1
        for key in range(len(line_data_value) - 1):
            if ord(line_data_value[key + 1]) - ord(line_data_value[key]) == 1:
                count += 1
            else:
                count = 1
                continue
            if count == self.pattern_len:
                return True
        return False

    def descending_pattern_check(self, line_data_value: str) -> bool:
        """Check if candidate value contain 4 and more descending chars or numbers sequences.

        Arg:
            line_data_value: string variable, credential candidate value

        Return:
            boolean variable. True if contain and False if not

        """
        count = 1
        for key in range(len(line_data_value) - 1):
            if ord(line_data_value[key]) - ord(line_data_value[key + 1]) == 1:
                count += 1
            else:
                count = 1
                continue
            if count == self.pattern_len:
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
        if len(line_data.value) < self.pattern_len:
            return True

        if self.equal_pattern_check(line_data.value):
            return True

        if self.ascending_pattern_check(line_data.value):
            return True

        if self.descending_pattern_check(line_data.value):
            return True

        return False
