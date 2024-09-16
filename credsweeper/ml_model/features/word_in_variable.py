from typing import List

import numpy as np

from credsweeper.credentials import Candidate
from credsweeper.ml_model.features.word_in import WordIn


class WordInVariable(WordIn):
    """Feature returns array of words matching in variable"""

    def __init__(self, words: List[str]) -> None:
        """Feature is true if candidate value contains at least one predefined word.

        Args:
            words: list of predefined words - MUST BE IN LOWER CASE

        """
        super().__init__(words)

    def extract(self, candidate: Candidate) -> np.ndarray:
        """Returns array of matching words for first line"""
        if variable := candidate.line_data_list[0].variable:
            return self.word_in_str(variable.lower())
        else:
            return np.zeros(shape=[self.dimension], dtype=np.int8)
