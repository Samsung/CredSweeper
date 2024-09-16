from typing import List

import numpy as np

from credsweeper.common.constants import CHUNK_SIZE
from credsweeper.credentials import Candidate
from credsweeper.ml_model.features.word_in import WordIn
from credsweeper.utils import Util


class WordInLine(WordIn):
    """Feature is true if line contains at least one word from predefined list."""

    def __init__(self, words: List[str]) -> None:
        """Feature returns array of matching words

        Args:
            words: list of predefined words - MUST BE IN LOWER CASE

        """
        super().__init__(words)

    def extract(self, candidate: Candidate) -> np.ndarray:
        """Returns true if any words in first line"""
        subtext = Util.subtext(candidate.line_data_list[0].line, candidate.line_data_list[0].value_start, CHUNK_SIZE)
        if subtext:
            return self.word_in_str(subtext.lower())
        else:
            return np.array([np.zeros(shape=[self.dimension], dtype=np.int8)])
