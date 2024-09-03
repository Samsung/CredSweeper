from typing import List, Any

import numpy as np

from credsweeper.credentials import Candidate
from credsweeper.ml_model.features.word_in import WordIn


class FileExtension(WordIn):
    """Categorical feature of file type.

    Parameters:
        extensions: extension labels

    """

    def __init__(self, extensions: List[str]) -> None:
        super().__init__(extensions)

    def __call__(self, candidates: List[Candidate]) -> np.ndarray:
        extension_set = set([candidate.line_data_list[0].file_type.lower() for candidate in candidates])
        return self.word_in_set(extension_set)

    def extract(self, candidate: Candidate) -> Any:
        raise NotImplementedError
