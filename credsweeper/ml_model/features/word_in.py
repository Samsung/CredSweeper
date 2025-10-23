from abc import abstractmethod
from typing import List, Any, Set, Union, Optional

import numpy as np

from credsweeper.credentials.candidate import Candidate
from credsweeper.ml_model.features.feature import Feature


class WordIn(Feature):
    """Abstract feature returns array with all matched words in a string"""

    def __init__(self, words: List[str]):
        super().__init__()
        self.dimension = 1 + len(words)
        # first item for "dead neuron"
        self.words: List[Optional[str]] = [None]
        self.words.extend(sorted(list(set(words))))
        self.enumerated_words = list(enumerate(self.words))
        if len(self.enumerated_words) != self.dimension:
            raise RuntimeError(f"Check duplicates:{words}")

    @abstractmethod
    def extract(self, candidate: Candidate) -> Any:
        raise NotImplementedError

    @property
    def zero(self) -> np.ndarray:
        """Returns zero filled array for case of empty input"""
        return np.zeros(shape=[self.dimension], dtype=np.int8)

    def word_in_(self, iterable_data: Union[str, List[str], Set[str]]) -> np.ndarray:
        """Returns array with words included in a string"""
        result: np.ndarray = self.zero
        for i, word in self.enumerated_words[1:]:
            if word in iterable_data:
                result[i] = 1
        if not np.any(result):
            # avoid dead neurons
            result[0] = 1
        return np.array([result])
