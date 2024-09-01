from abc import abstractmethod
from typing import List, Any, Tuple, Set

import numpy as np

from credsweeper.credentials import Candidate
from credsweeper.ml_model.features.feature import Feature


class WordIn(Feature):
    """Abstract feature returns array with all matched words in a string"""

    def __init__(self, words: List[str]):
        super().__init__()
        self.dimension = len(words)
        self.words = sorted(list(set(words)))
        self.enumerated_words = list(enumerate(self.words))
        if len(self.enumerated_words) != self.dimension:
            raise RuntimeError(f"Check duplicates:{words}")

    @property
    def enumerated_words(self) -> List[Tuple[int, str]]:
        """getter for speedup"""
        return self.__enumerated_words

    @enumerated_words.setter
    def enumerated_words(self, enumerated_words: List[Tuple[int, str]]) -> None:
        """setter for speedup"""
        self.__enumerated_words = enumerated_words

    @property
    def dimension(self) -> int:
        """getter"""
        return self.__dimension

    @dimension.setter
    def dimension(self, dimension: int) -> None:
        """setter"""
        self.__dimension = dimension

    @abstractmethod
    def extract(self, candidate: Candidate) -> Any:
        raise NotImplementedError

    def word_in_str(self, a_string: str) -> np.ndarray:
        """Returns array with words included in a string"""
        result = np.zeros(shape=[self.dimension], dtype=np.int8)
        for i, word in self.enumerated_words:
            if word in a_string:
                result[i] = 1
        return np.array([result])

    def word_in_set(self, a_strings_set: Set[str]) -> np.ndarray:
        """Returns array with words matches in a_strings_set"""
        result = np.zeros(shape=[self.dimension], dtype=np.int8)
        for i, word in self.enumerated_words:
            if word in a_strings_set:
                result[i] = 1
        return np.array([result])
