from abc import abstractmethod
from functools import cached_property
from typing import List, Any, Set, Union

import numpy as np

from credsweeper.credentials.candidate import Candidate
from credsweeper.ml_model.features.feature import Feature


class WordIn(Feature):
    """Abstract feature returns array with all matched words in a string"""

    def __init__(self, words: List[str]):
        super().__init__()
        self.dimension = 1 + len(words)
        self.words = [None]
        self.words.extend(sorted(list(set(words))))
        self.enumerated_words = list(enumerate(self.words))
        if len(self.enumerated_words) != self.dimension:
            raise RuntimeError(f"Check duplicates:{words}")

    @abstractmethod
    def extract(self, candidate: Candidate) -> Any:
        raise NotImplementedError

    def word_in_(self, a_string: Union[str, Set[str]]) -> np.ndarray:
        """Returns array with words included in a string"""
        result: np.ndarray = np.zeros(shape=[self.dimension], dtype=np.int8)
        for i, word in self.enumerated_words[1:]:
            if word in a_string:
                result[i] = 1
        if not np.any(result):
            # avoid dead neurons
            result[0] = 1
        return np.array([result])

    @cached_property
    def zero(self) -> np.ndarray:
        """Returns zero filled array for case of empty input"""
        result: np.ndarray = np.zeros(shape=[self.dimension], dtype=np.int8)
        result[0] = 1
        return np.array([result])
