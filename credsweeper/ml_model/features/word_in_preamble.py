import numpy as np

from credsweeper.common.constants import ML_HUNK
from credsweeper.credentials.candidate import Candidate
from credsweeper.ml_model.features.word_in import WordIn


class WordInPreamble(WordIn):
    """Feature is true if line contains at least one word from predefined list."""

    def extract(self, candidate: Candidate) -> np.ndarray:
        """Returns true if any words in line before variable or value"""
        if 0 <= candidate.line_data_list[0].variable_start:
            preamble_start = 0 if ML_HUNK >= candidate.line_data_list[0].variable_start \
                else candidate.line_data_list[0].variable_start - ML_HUNK
            preamble = candidate.line_data_list[0].line[preamble_start:candidate.line_data_list[0].
                                                        variable_start].strip()
        else:
            preamble_start = 0 if ML_HUNK >= candidate.line_data_list[0].value_start \
                else candidate.line_data_list[0].value_start - ML_HUNK
            preamble = candidate.line_data_list[0].line[preamble_start:candidate.line_data_list[0].value_start].strip()

        if preamble:
            return self.word_in_str(preamble.lower())
        else:
            return np.array([np.zeros(shape=[self.dimension], dtype=np.int8)])
