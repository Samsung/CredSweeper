from typing import Tuple

from credsweeper.credentials.line_data import LineData


class CandidateKey:
    """Class used to identify credential candidates.

    Candidates that detected same value on same string in a same file would have identical CandidateKey
    """

    def __init__(self, line_data: LineData):
        self.path: str = line_data.path
        self.line_num: int = line_data.line_num
        self.value: str = line_data.value
        self.key: Tuple[str, int, str] = (self.path, self.line_num, self.value)

    def __hash__(self):
        return hash(self.key)

    def __eq__(self, other):
        return self.key == other.key

    def __ne__(self, other):
        return not (self == other)
