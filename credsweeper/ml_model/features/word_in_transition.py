from typing import List

import numpy as np

from credsweeper.credentials import Candidate
from credsweeper.ml_model.features.word_in import WordIn


class WordInTransition(WordIn):
    """Feature is true if line contains at least one word from predefined list."""

    def __init__(self, words: List[str]) -> None:
        """Feature returns array of matching words

        Args:
            words: list of predefined words - MUST BE IN LOWER CASE

        """
        super().__init__(words)

    def extract(self, candidate: Candidate) -> np.ndarray:
        """Returns true if any words between variable and value"""
        if 0 <= candidate.line_data_list[0].variable_end < candidate.line_data_list[0].value_start:
            transition = candidate.line_data_list[0].line[candidate.line_data_list[0].variable_end:candidate.
                                                          line_data_list[0].value_start].strip()
        else:
            transition = ''

        if transition:
            return self.word_in_str(transition.lower())
        else:
            return np.array([np.zeros(shape=[self.dimension], dtype=np.int8)])
