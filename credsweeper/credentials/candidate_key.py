from typing import Tuple

from credsweeper.credentials.line_data import LineData


class CandidateKey:
    """Class used to identify credential candidates.

    Candidates that detected same value on same string in a same file would have identical CandidateKey
    """

    def __init__(self, line_data: LineData):
        self.path: str = line_data.path
        self.line_num: int = line_data.line_num
        self.value_start: int = line_data.value_start
        self.value_end: int = line_data.value_end
        self.key: Tuple[str, int, int, int] = (self.path, self.line_num, self.value_start, self.value_end)
        self.__line = line_data.line

    def __hash__(self):
        return hash(self.key)

    def __eq__(self, other):
        return self.key == other.key

    def __ne__(self, other):
        return not bool(self == other)

    def __repr__(self) -> str:
        return f"{self.key}:{self.__line}"
