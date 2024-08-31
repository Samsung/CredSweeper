"""Most rules are described in 'Secrets in Source Code: Reducing False Positives Using Machine Learning'."""
from pathlib import Path
from typing import List, Any

import numpy as np

from credsweeper.credentials import Candidate
from credsweeper.ml_model.features.word_in import WordIn


class WordInPath(WordIn):
    """Categorical feature that corresponds to words in path (POSIX, lowercase)"""

    def __init__(self, words: List[str]) -> None:
        """WordInPath constructor

        Args:
            words: list of predefined words - MUST BE IN LOWER CASE & POSIX

        """
        super().__init__(words)

    def __call__(self, candidates: List[Candidate]) -> np.ndarray:
        # actually there must be one path because the candidates are grouped before
        candidate_path = Path( candidates[0].line_data_list[0].path).as_posix().lower()
        if candidate_path:
            return self.word_in_str(candidate_path.lower())
        else:
            return np.zeros(shape=[self.dimension], dtype=np.int8)

    def extract(self, candidate: Candidate) -> Any:
        raise NotImplementedError

