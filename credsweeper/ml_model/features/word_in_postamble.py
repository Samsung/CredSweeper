import numpy as np

from credsweeper.common.constants import ML_HUNK
from credsweeper.credentials.candidate import Candidate
from credsweeper.ml_model.features.word_in import WordIn


class WordInPostamble(WordIn):
    """Feature is true if line contains at least one word from predefined list."""

    def extract(self, candidate: Candidate) -> np.ndarray:
        """Returns true if any words in a part of line after value"""
        postamble_end = len(candidate.line_data_list[0].line) \
            if len(candidate.line_data_list[0].line) < candidate.line_data_list[0].value_end + ML_HUNK \
            else candidate.line_data_list[0].value_end + ML_HUNK
        postamble = candidate.line_data_list[0].line[candidate.line_data_list[0].value_end:postamble_end].strip()

        if postamble:
            return self.word_in_str(postamble.lower())
        else:
            return np.array([np.zeros(shape=[self.dimension], dtype=np.int8)])
