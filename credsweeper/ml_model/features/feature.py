from abc import ABC, abstractmethod
from typing import List, Any

import numpy as np

from credsweeper.credentials import Candidate


class Feature(ABC):
    """Base class for features."""

    def __init__(self):
        self.words = []

    def __call__(self, candidates: List[Candidate]) -> np.ndarray:
        """Call base class for features.

        Args:
            candidates: list of candidates to extract features

        """
        return np.array([self.extract(candidate) for candidate in candidates])

    @abstractmethod
    def extract(self, candidate: Candidate) -> Any:
        """Abstract method of base class"""
        raise NotImplementedError

    @property
    def words(self) -> List[str]:
        """getter"""
        return self.__words

    @words.setter
    def words(self, words: List[str]) -> None:
        """setter"""
        self.__words = words

    def any_word_in_(self, a_string: str) -> bool:
        """Returns true if any words in a string"""
        for i in self.words:
            if i in a_string:
                return True
        return False
