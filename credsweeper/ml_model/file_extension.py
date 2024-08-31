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

