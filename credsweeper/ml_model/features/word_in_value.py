from typing import List

import numpy as np

from credsweeper.credentials import Candidate
from credsweeper.ml_model.features.word_in import WordIn


class WordInValue(WordIn):
    """Feature returns true if candidate value contains at least one word from predefined list."""

    def __init__(self, words: List[str]) -> None:
        """Feature is true if candidate value contains at least one predefined word.

        Args:
            words: list of predefined words - MUST BE IN LOWER CASE and SORTED (preferred)

        """
        super().__init__(words)

    def extract(self, candidate: Candidate) -> np.ndarray:
        """Returns array of matching words for first line"""
        if value := candidate.line_data_list[0].value:
            return self.word_in_str(value.lower())
        else:
            return np.array([np.zeros(shape=[self.dimension], dtype=np.int8)])
