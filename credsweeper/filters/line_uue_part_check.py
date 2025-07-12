import re
from typing import Optional

from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters.filter import Filter


class LineUUEPartCheck(Filter):
    """Checks that line is not a part of UU encoding only for maximal line"""
    uue_string = re.compile(r"^M[!-`]{60}$")

    def __init__(self, config: Optional[Config] = None) -> None:
        pass

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, if need to filter candidate and False if left

        """
        if not line_data.line:
            return True
        if 61 != target.line_len:
            return False
        line = target.line
        if LineUUEPartCheck.uue_string.match(line):
            # to be sure - check two lines: before and/or after
            if 0 < line_data.line_pos:
                previous_line = target.lines[line_data.line_pos - 1]
                if LineUUEPartCheck.uue_string.match(previous_line):
                    return True

            if len(target.lines) > 1 + line_data.line_pos:
                next_line = target.lines[line_data.line_pos + 1]
                if LineUUEPartCheck.uue_string.match(next_line):
                    return True

        return False
