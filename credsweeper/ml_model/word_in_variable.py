"""Most rules are described in 'Secrets in Source Code: Reducing False Positives Using Machine Learning'."""
import contextlib
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Any, Dict, Tuple, Set

import numpy as np

from credsweeper.common.constants import Base, Chars, CHUNK_SIZE
from credsweeper.credentials import Candidate
from credsweeper.ml_model.word_in import WordIn
from credsweeper.utils import Util




class WordInVariable(WordIn):
    """Feature returns array of words matching in variable"""

    def __init__(self, words: List[str]) -> None:
        """Feature is true if candidate value contains at least one predefined word.

        Args:
            words: list of predefined words - MUST BE IN LOWER CASE

        """
        super().__init__(words)

    def extract(self, candidate: Candidate) ->  np.ndarray:
        """Returns array of matching words for first line"""
        if candidate.line_data_list[0].variable:
            return self.word_in_str(candidate.line_data_list[0].variable.lower())
        else:
            return np.zeros(shape=[self.dimension], dtype=np.int8)

