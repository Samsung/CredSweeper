import os.path
from pathlib import Path
from typing import List, Any

import numpy as np

from credsweeper.credentials.candidate import Candidate
from credsweeper.ml_model.features.word_in import WordIn


class WordInPath(WordIn):
    """Categorical feature that corresponds to words in path (POSIX, lowercase)"""

    def __call__(self, candidates: List[Candidate]) -> np.ndarray:
        # actually there must be one path because the candidates are grouped before
        if file_path := candidates[0].line_data_list[0].path:
            path = Path(file_path)
            # apply ./ for normalised path to detect "/src" for relative path
            posix_lower_path = path.as_posix().lower() if path.is_absolute() else f"./{path.as_posix().lower()}"
            # prevent extra confusion from the same word in extension
            path_without_extension, _ = os.path.splitext(posix_lower_path)
            return self.word_in_(path_without_extension)
        return np.array([self.zero])

    def extract(self, candidate: Candidate) -> Any:
        raise NotImplementedError
