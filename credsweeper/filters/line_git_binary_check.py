import base64
import contextlib
import re

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter


class LineGitBinaryCheck(Filter):
    """Checks that line is not a part of git binary patch"""
    base85string = re.compile(r"^[A-Za-z][0-9A-Za-z!#$%&()*+;<=>?@^_`{|}~-]{6,65}$")

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
        if line_data.line is None:
            return True
        if 66 < target.line_strip_len:
            return False
        line = target.line_strip
        len_line = len(line)

        # https://github.com/git/git/blob/master/base85.c

        if 6 <= len_line and 0 == ((len_line - 1) % 5) and LineGitBinaryCheck.base85string.match(line):
            size = ord(line[0])
            if 65 <= size <= 90:  # A-Z
                size -= 64
            elif 97 <= size <= 122:  # a-z
                size -= 70
            else:
                return False
            with contextlib.suppress(Exception):
                decoded = base64.b85decode(line[1:])
                return len(decoded) == size

        return False
