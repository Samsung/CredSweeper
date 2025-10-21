import numpy as np

from credsweeper.credentials.candidate import Candidate
from credsweeper.ml_model.features.word_in import WordIn


class WordInTransition(WordIn):
    """Feature is true if line contains at least one word from predefined list."""

    def extract(self, candidate: Candidate) -> np.ndarray:
        """Returns true if any words between variable and value"""
        if 0 <= candidate.line_data_list[0].variable_end < candidate.line_data_list[0].value_start:
            transition = candidate.line_data_list[0].line[candidate.line_data_list[0].variable_end:candidate.
                                                          line_data_list[0].value_start].strip()
        else:
            transition = ''

        return self.word_in_(transition.lower()) if transition else np.array([self.zero])
